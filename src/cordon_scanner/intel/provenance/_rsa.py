"""RSA signature verification, PKCS #1 v1.5 and PSS, verify-only, in pure Python (RFC 8017).

Why: OpenPGP signatures on Helm charts, Ansible collections and distribution packages are
mostly RSA, and so are some certificate chains. The standard library has modular exponentiation
and the hashes; the rest is the encoding, written here.

PKCS #1 v1.5 is verified the only safe way: the expected encoding is built from the digest and
compared with the recovered one byte for byte. A verifier that instead parses the recovered
block is the one that accepts forgeries (Bleichenbacher's 2006 attack on lenient parsers). PSS
follows EMSA-PSS-VERIFY step by step. Every Wycheproof RSA family runs in
`tests/unit/intel/provenance/test_rsa.py`.

Keys under 2048 bits are refused: they are not a signature anyone should trust.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import ClassVar

from cordon_scanner.foundation.signatures.der import Der, DerError


class Rsa:
    """`Rsa.verify_pkcs1(...)`, `Rsa.verify_pss(...)`, and the key reader."""

    RSA_ENCRYPTION: ClassVar[str] = "1.2.840.113549.1.1.1"
    MIN_BITS: ClassVar[int] = 2048
    MAX_BITS: ClassVar[int] = 16384
    #: The DER DigestInfo prefix for each hash (RFC 8017 section 9.2, note 1).
    DIGEST_INFO: ClassVar[dict[str, bytes]] = {
        "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
        "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
        "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
        "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
        "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    }

    @staticmethod
    def public_key(spki_der: bytes) -> tuple[int, int]:
        """(n, e) of a DER SubjectPublicKeyInfo holding an RSA key."""
        spki = Der.parse(spki_der, Der.SEQUENCE).children()
        if len(spki) != 2:
            raise DerError("a key info of the wrong shape")
        algorithm = spki[0].expect(Der.SEQUENCE).children()
        if not algorithm or algorithm[0].oid() != Rsa.RSA_ENCRYPTION:
            raise DerError("not an RSA key")
        if len(algorithm) == 2 and algorithm[1].tag != Der.NULL:
            raise DerError("RSA key parameters that are not NULL")
        return Rsa.raw_key(spki[1].bit_string())

    @staticmethod
    def raw_key(der: bytes) -> tuple[int, int]:
        """(n, e) of a DER RSAPublicKey."""
        parts = Der.parse(der, Der.SEQUENCE).children()
        if len(parts) != 2:
            raise DerError("an RSA key of the wrong shape")
        return Rsa.checked(parts[0].integer(), parts[1].integer())

    @staticmethod
    def checked(n: int, e: int, *, min_bits: int | None = None) -> tuple[int, int]:
        if not (min_bits or Rsa.MIN_BITS) <= n.bit_length() <= Rsa.MAX_BITS or n % 2 == 0:
            raise DerError("an RSA modulus out of range")
        if e < 3 or e % 2 == 0 or e >= n:
            raise DerError("an RSA exponent out of range")
        return n, e

    @staticmethod
    def _recover(key: tuple[int, int], signature: bytes) -> bytes | None:
        n, e = key
        k = (n.bit_length() + 7) // 8
        if len(signature) != k:
            return None
        s = int.from_bytes(signature, "big")
        if s >= n:
            return None
        return pow(s, e, n).to_bytes(k, "big")

    @staticmethod
    def verify_pkcs1(
        key: tuple[int, int], message: bytes, signature: bytes, hash_name: str
    ) -> bool:
        return Rsa.verify_pkcs1_digest(
            key, hashlib.new(hash_name, message).digest(), signature, hash_name
        )

    @staticmethod
    def verify_pkcs1_digest(
        key: tuple[int, int], digest: bytes, signature: bytes, hash_name: str
    ) -> bool:
        """PKCS #1 v1.5 over a digest already taken (OpenPGP hashes its own trailer in)."""
        prefix = Rsa.DIGEST_INFO.get(hash_name)
        if prefix is None or len(digest) != hashlib.new(hash_name).digest_size:
            return False
        em = Rsa._recover(key, signature)
        if em is None:
            return False
        t = prefix + digest
        k = len(em)
        if k < len(t) + 11:
            return False
        expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return hmac.compare_digest(em, expected)

    @staticmethod
    def verify_pss(
        key: tuple[int, int],
        message: bytes,
        signature: bytes,
        hash_name: str,
        salt_length: int,
        mgf_hash: str | None = None,
    ) -> bool:
        em_full = Rsa._recover(key, signature)
        if em_full is None:
            return False
        n = key[0]
        em_bits = n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        em = em_full[len(em_full) - em_len :]
        if len(em_full) - em_len and any(em_full[: len(em_full) - em_len]):
            return False
        h_len = hashlib.new(hash_name).digest_size
        m_hash = hashlib.new(hash_name, message).digest()
        if em_len < h_len + salt_length + 2 or em[-1] != 0xBC:
            return False
        masked, h = em[: em_len - h_len - 1], em[em_len - h_len - 1 : -1]
        unused = 8 * em_len - em_bits
        if masked[0] >> (8 - unused) if unused else 0:
            return False
        mask = Rsa._mgf1(h, len(masked), mgf_hash or hash_name)
        db = bytearray(a ^ b for a, b in zip(masked, mask, strict=True))
        if unused:
            db[0] &= 0xFF >> unused
        pad = em_len - h_len - salt_length - 2
        if any(db[:pad]) or db[pad] != 1:
            return False
        salt = bytes(db[len(db) - salt_length :]) if salt_length else b""
        h2 = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
        return hmac.compare_digest(h, h2)

    @staticmethod
    def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
            counter += 1
        return bytes(out[:length])


__all__ = ["Rsa"]
