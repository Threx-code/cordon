"""X.509 certificates and public keys, read strictly, for verifying signatures and chains.

What provenance needs from a certificate, and nothing it does not: the signed part (`tbs`) and
the issuer's signature over it, the issuer and subject names (compared as their exact DER
encodings, never re-encoded), the validity window, the public key, and the extensions -- the
subject alternative names and the Fulcio identity claims a signing policy is checked against.

Strict as `_der` is strict. A certificate is refused, not interpreted, when:

- it is not version 3, or its outer and inner signature algorithms differ (RFC 5280 4.1.1.2:
  an attacker who could make them differ could have a verifier check the wrong algorithm);
- an extension appears twice, or a critical extension is one this reader does not understand
  (RFC 5280 4.2: a critical extension that is not processed must reject the certificate);
- any field is not in its distinguished encoding.

`PublicKey` verifies with the project's own ECDSA, RSA and Ed25519 (`_ecdsa`, `_rsa`,
`_ed25519`), chosen by the key and the signature algorithm together: a key is never used with an
algorithm of another family.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import ClassVar

from cordon_scanner.foundation.signatures.der import Der, DerError
from cordon_scanner.foundation.signatures.ecdsa import Ecdsa
from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.intel.provenance._rsa import Rsa


class PublicKey:
    """A public key read from a SubjectPublicKeyInfo: EC (P-256, P-384), RSA or Ed25519."""

    ED25519: ClassVar[str] = "1.3.101.112"
    #: Signature algorithm OID -> (key family, hash).
    ALGORITHMS: ClassVar[dict[str, tuple[str, str | None]]] = {
        "1.2.840.10045.4.3.2": ("ec", "sha256"),
        "1.2.840.10045.4.3.3": ("ec", "sha384"),
        "1.2.840.10045.4.3.4": ("ec", "sha512"),
        "1.2.840.113549.1.1.11": ("rsa", "sha256"),
        "1.2.840.113549.1.1.12": ("rsa", "sha384"),
        "1.2.840.113549.1.1.13": ("rsa", "sha512"),
        "1.3.101.112": ("ed25519", None),
    }

    def __init__(self, family: str, key: object, spki: bytes) -> None:
        self.family, self.key, self.spki = family, key, spki

    @staticmethod
    def from_spki(spki: bytes) -> PublicKey:
        info = Der.parse(spki, Der.SEQUENCE).children()
        if len(info) != 2:
            raise DerError("a key info of the wrong shape")
        algorithm = info[0].expect(Der.SEQUENCE).children()
        oid = algorithm[0].oid() if algorithm else ""
        if oid == Ecdsa.EC_PUBLIC_KEY:
            return PublicKey("ec", Ecdsa.public_key(spki), spki)
        if oid == Rsa.RSA_ENCRYPTION:
            return PublicKey("rsa", Rsa.public_key(spki), spki)
        if oid == PublicKey.ED25519:
            if len(algorithm) != 1:
                raise DerError("Ed25519 key parameters must be absent")
            raw = info[1].bit_string()
            if len(raw) != 32:
                raise DerError("an Ed25519 key of the wrong length")
            return PublicKey("ed25519", raw, spki)
        raise DerError(f"a key algorithm not supported: {oid}")

    @staticmethod
    def from_pem(pem: str) -> PublicKey:
        return PublicKey.from_spki(Pem.decode(pem, "PUBLIC KEY"))

    #: verdicts already reached, by (key, hash, digest of the message, signature): verification
    #: is a pure function of these, and a certificate authority's signature over its
    #: intermediate recurs in every bundle it issues
    VERDICTS: ClassVar[OrderedDict[tuple[bytes, str | None, bytes, bytes], bool]] = OrderedDict()
    VERDICTS_MAX: ClassVar[int] = 4096
    VERDICTS_LOCK: ClassVar[threading.Lock] = threading.Lock()

    def verify(self, message: bytes, signature: bytes, hash_name: str | None) -> bool:
        """Whether `signature` signs `message`: ECDSA in DER, RSA PKCS #1 v1.5, or Ed25519.
        False for anything malformed, and for a hash this family is not used with."""
        key = (self.spki, hash_name, hashlib.sha512(message).digest(), bytes(signature))
        with PublicKey.VERDICTS_LOCK:
            cached = PublicKey.VERDICTS.get(key)
            if cached is not None:
                PublicKey.VERDICTS.move_to_end(key)
                return cached
        verdict = self._verify(message, signature, hash_name)
        with PublicKey.VERDICTS_LOCK:
            PublicKey.VERDICTS[key] = verdict
            if len(PublicKey.VERDICTS) > PublicKey.VERDICTS_MAX:
                PublicKey.VERDICTS.popitem(last=False)
        return verdict

    def _verify(self, message: bytes, signature: bytes, hash_name: str | None) -> bool:
        if self.family == "ec" and hash_name:
            return Ecdsa.verify(self.key, message, signature, hash_name)  # type: ignore[arg-type]
        if self.family == "rsa" and hash_name:
            return Rsa.verify_pkcs1(self.key, message, signature, hash_name)  # type: ignore[arg-type]
        if self.family == "ed25519" and hash_name is None:
            return Ed25519.verify(self.key, message, signature)  # type: ignore[arg-type]
        return False

    def verify_algorithm(self, oid: str, message: bytes, signature: bytes) -> bool:
        """`verify` under a signature algorithm named by its OID, which must suit this key."""
        family, hash_name = PublicKey.ALGORITHMS.get(oid, ("", None))
        return family == self.family and self.verify(message, signature, hash_name)


@dataclass(frozen=True)
class Extension:
    critical: bool
    value: bytes


@dataclass(frozen=True)
class Certificate:
    """One X.509 v3 certificate, read strictly (see the module docstring)."""

    raw: bytes
    tbs: bytes
    signature_algorithm: str
    signature: bytes
    serial: int
    issuer: bytes
    subject: bytes
    not_before: dt.datetime
    not_after: dt.datetime
    spki: bytes
    extensions: dict[str, Extension] = field(default_factory=dict)

    #: Extensions a certificate here may mark critical: basic constraints, key usage, extended
    #: key usage, subject alternative name, name constraints, certificate policies.
    UNDERSTOOD_CRITICAL: ClassVar[frozenset[str]] = frozenset(
        {"2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.30", "2.5.29.32"}
    )
    SAN: ClassVar[str] = "2.5.29.17"
    BASIC_CONSTRAINTS: ClassVar[str] = "2.5.29.19"
    KEY_USAGE: ClassVar[str] = "2.5.29.15"
    EXTENDED_KEY_USAGE: ClassVar[str] = "2.5.29.37"
    CODE_SIGNING: ClassVar[str] = "1.3.6.1.5.5.7.3.3"
    #: Embedded signed certificate timestamps (RFC 6962 3.3).
    SCT_LIST: ClassVar[str] = "1.3.6.1.4.1.11129.2.4.2"
    #: The CT precertificate poison (RFC 6962 3.1): present only on a precertificate.
    POISON: ClassVar[str] = "1.3.6.1.4.1.11129.2.4.3"
    UNDERSTOOD_CRITICAL_CT: ClassVar[frozenset[str]] = frozenset({POISON})

    @staticmethod
    def from_der(raw: bytes) -> Certificate:
        outer = Der.parse(raw, Der.SEQUENCE).children()
        if len(outer) != 3:
            raise DerError("a certificate of the wrong shape")
        tbs, algorithm, signature = outer
        outer_oid = Certificate._algorithm(algorithm)
        fields = tbs.expect(Der.SEQUENCE).children()
        at = 0
        if fields and fields[0].tag == 0xA0:  # [0] EXPLICIT version
            version = Der.parse(fields[0].body).integer()
            if version != 2:
                raise DerError("not an X.509 v3 certificate")
            at = 1
        else:
            raise DerError("not an X.509 v3 certificate")
        serial = fields[at].integer(unsigned=False)
        inner_oid = Certificate._algorithm(fields[at + 1])
        if inner_oid != outer_oid:
            raise DerError("the inner and outer signature algorithms differ")
        issuer = fields[at + 2].expect(Der.SEQUENCE).raw
        validity = fields[at + 3].expect(Der.SEQUENCE).children()
        if len(validity) != 2:
            raise DerError("a validity of the wrong shape")
        subject = fields[at + 4].expect(Der.SEQUENCE).raw
        spki = fields[at + 5].expect(Der.SEQUENCE).raw
        extensions: dict[str, Extension] = {}
        for extra in fields[at + 6 :]:
            if extra.tag in (0x81, 0x82):  # issuer/subject unique IDs: allowed, unused here
                continue
            if extra.tag != 0xA3:
                raise DerError("an unexpected certificate field")
            for ext in Der.parse(extra.body, Der.SEQUENCE).children():
                parts = ext.expect(Der.SEQUENCE).children()
                oid = parts[0].oid()
                critical = False
                if len(parts) == 3:
                    critical = parts[1].boolean()
                    if not critical:
                        raise DerError("a DEFAULT FALSE written out")  # DER omits a default
                elif len(parts) != 2:
                    raise DerError("an extension of the wrong shape")
                value = parts[-1].expect(Der.OCTET_STRING).body
                if oid in extensions:
                    raise DerError(f"extension {oid} appears twice")
                understood = Certificate.UNDERSTOOD_CRITICAL | Certificate.UNDERSTOOD_CRITICAL_CT
                if critical and oid not in understood:
                    raise DerError(f"a critical extension not understood: {oid}")
                extensions[oid] = Extension(critical, value)
        return Certificate(
            raw=raw,
            tbs=tbs.raw,
            signature_algorithm=outer_oid,
            signature=signature.bit_string(),
            serial=serial,
            issuer=issuer,
            subject=subject,
            not_before=Certificate._time(validity[0]),
            not_after=Certificate._time(validity[1]),
            spki=spki,
            extensions=extensions,
        )

    @staticmethod
    def from_pem(pem: str) -> list[Certificate]:
        return [Certificate.from_der(der) for der in Pem.decode_all(pem, "CERTIFICATE")]

    # -- fields ---------------------------------------------------------------

    @staticmethod
    def _algorithm(node: Der) -> str:
        parts = node.expect(Der.SEQUENCE).children()
        if not parts:
            raise DerError("an empty algorithm identifier")
        oid = parts[0].oid()
        family = PublicKey.ALGORITHMS.get(oid, ("", None))[0]
        # ECDSA and Ed25519 identifiers carry no parameters; RSA's carry an explicit NULL.
        if family in ("ec", "ed25519") and len(parts) != 1:
            raise DerError("signature algorithm parameters that must be absent")
        if family == "rsa" and (len(parts) != 2 or parts[1].tag != Der.NULL or parts[1].body):
            raise DerError("RSA signature algorithm parameters that are not NULL")
        return oid

    @staticmethod
    def _time(node: Der) -> dt.datetime:
        text = node.body.decode("ascii", "strict")
        if node.tag == Der.UTC_TIME:
            if len(text) != 13 or not text.endswith("Z"):
                raise DerError("a UTCTime not in YYMMDDHHMMSSZ")
            year = int(text[:2])
            text = ("19" if year >= 50 else "20") + text
        elif node.tag == Der.GENERALIZED_TIME:
            if len(text) != 15 or not text.endswith("Z"):
                raise DerError("a GeneralizedTime not in YYYYMMDDHHMMSSZ")
        else:
            raise DerError("not a time")
        return dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=dt.UTC)

    def public_key(self) -> PublicKey:
        return PublicKey.from_spki(self.spki)

    def signed_by(self, issuer: PublicKey) -> bool:
        return issuer.verify_algorithm(self.signature_algorithm, self.tbs, self.signature)

    def valid_at(self, when: dt.datetime) -> bool:
        return self.not_before <= when <= self.not_after

    def is_ca(self) -> bool:
        ext = self.extensions.get(Certificate.BASIC_CONSTRAINTS)
        if ext is None:
            return False
        parts = Der.parse(ext.value, Der.SEQUENCE).children()
        return bool(parts) and parts[0].tag == Der.BOOLEAN and parts[0].boolean()

    def extended_key_usages(self) -> set[str]:
        ext = self.extensions.get(Certificate.EXTENDED_KEY_USAGE)
        if ext is None:
            return set()
        return {child.oid() for child in Der.parse(ext.value, Der.SEQUENCE).children()}

    def subject_alternative_names(self) -> list[tuple[str, str]]:
        """(kind, value) for each email (`email`) and URI (`uri`) alternative name."""
        ext = self.extensions.get(Certificate.SAN)
        if ext is None:
            return []
        out: list[tuple[str, str]] = []
        for name in Der.parse(ext.value, Der.SEQUENCE).children():
            if name.tag == 0x81:
                out.append(("email", name.body.decode("ascii", "strict")))
            elif name.tag == 0x86:
                out.append(("uri", name.body.decode("ascii", "strict")))
        return out

    def extension_text(self, oid: str, *, der_string: bool) -> str | None:
        """An extension's value as text: a DER string (`der_string`), or raw UTF-8 bytes (the
        form Fulcio's first claim extensions use)."""
        ext = self.extensions.get(oid)
        if ext is None:
            return None
        try:
            return Der.parse(ext.value).text() if der_string else ext.value.decode("utf-8")
        except (DerError, UnicodeDecodeError):
            return None


class Pem:
    """PEM armour, strictly: the named label, base64 that decodes exactly."""

    @staticmethod
    def decode_all(text: str, label: str) -> list[bytes]:
        begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
        out: list[bytes] = []
        at = 0
        while True:
            start = text.find(begin, at)
            if start < 0:
                return out
            stop = text.find(end, start)
            if stop < 0:
                raise DerError("an unterminated PEM block")
            body = "".join(text[start + len(begin) : stop].split())
            try:
                out.append(base64.b64decode(body, validate=True))
            except ValueError as exc:
                raise DerError("PEM that is not base64") from exc
            at = stop + len(end)

    @staticmethod
    def decode(text: str, label: str) -> bytes:
        blocks = Pem.decode_all(text, label)
        if len(blocks) != 1:
            raise DerError(f"expected one {label}, found {len(blocks)}")
        return blocks[0]


__all__ = ["Certificate", "Extension", "Pem", "PublicKey"]
