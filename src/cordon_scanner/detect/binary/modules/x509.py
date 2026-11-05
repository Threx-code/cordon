"""X.509, as Authenticode uses it: distinguished names rendered the way OpenSSL prints them,
certificates with their validity, issuer and key, the public keys they carry, and the walk from a
signer's certificate up the chain the signature itself ships.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.der import BadDer, Clock, Encode, Hash, Tlv
from cordon_scanner.detect.binary.modules.layout import Cursor
from cordon_scanner.detect.binary.modules.oids import ObjectIds
from cordon_scanner.foundation.signatures.dsa import Dsa
from cordon_scanner.foundation.signatures.ecdsa import Ecdsa


class X500:
    """An X.509 Name: its entries in order, OpenSSL's one-line form, and its comparison key."""

    #: universal tags an entry's value may carry (``B_ASN1_PRINTABLE``); any other fails
    ALLOWED: ClassVar[frozenset[int]] = frozenset(
        {18, 19, 20, 22, 3, 28, 30, 12, 16, 7, 8, 9, 10, 11, 13, 14, 15, 29}
    )
    #: tags whose values are compared case- and space-folded (``ASN1_MASK_CANON``)
    FOLDED: ClassVar[frozenset[int]] = frozenset({12, 30, 28, 19, 20, 22, 26})
    ONE_LINE_MAX: ClassVar[int] = 255

    def __init__(self, raw: bytes, rdns: list[list[tuple[str, int, bytes]]]) -> None:
        self.raw, self.rdns = raw, rdns
        self.key = tuple(tuple(sorted(X500._fold(e) for e in rdn)) for rdn in rdns if rdn)

    @staticmethod
    def parse(node: Tlv) -> X500:
        rdns: list[list[tuple[str, int, bytes]]] = []
        for rdn in node.row():
            entries: list[tuple[str, int, bytes]] = []
            for entry in rdn.bag():
                oid_node, value = entry.row(2)
                oid = oid_node.object_id()
                if value.klass != Tlv.UNIVERSAL or value.tag not in X500.ALLOWED:
                    raise BadDer("a name value of a type OpenSSL does not allow")
                if value.tag == 16:
                    data = value.span
                elif value.tag == 3:
                    joined = value.joined()
                    data = joined[1:] if joined else b""
                else:
                    data = value.joined()
                entries.append((oid, value.tag, data))
            rdns.append(entries)
        return X500(node.span, rdns)

    @staticmethod
    def _fold(entry: tuple[str, int, bytes]) -> tuple[str, int, bytes]:
        oid, tag, data = entry
        if tag not in X500.FOLDED:
            return oid, tag, data
        try:
            if tag == 12:
                text = data.decode("utf-8")
            elif tag == 30:
                if len(data) % 2:
                    raise BadDer("a BMPString of odd length")
                text = data.decode("utf-16-be", "surrogatepass")
            elif tag == 28:
                if len(data) % 4:
                    raise BadDer("a UniversalString of the wrong length")
                text = data.decode("utf-32-be")
            else:
                text = data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise BadDer("a name value not in its encoding") from exc
        blanks = b" \t\n\v\f\r"
        utf8 = text.encode("utf-8", "surrogatepass").strip(blanks)
        out = bytearray()
        i = 0
        while i < len(utf8):
            ch = utf8[i]
            if ch >= 0x80:
                out.append(ch)
                i += 1
            elif ch in blanks:
                out.append(0x20)
                while i < len(utf8) and utf8[i] in blanks:
                    i += 1
            else:
                out.append(ch + 32 if 0x41 <= ch <= 0x5A else ch)
                i += 1
        return oid, 12, bytes(out)

    def one_line(self) -> bytes:
        """``X509_NAME_oneline`` into the parser's 256-byte buffer: ``/C=US/O=...``, a byte outside
        printable ASCII as ``\\xHH``, entries that would not fit left off."""
        out = bytearray()
        for rdn in self.rdns:
            for oid, tag, data in rdn:
                names = ObjectIds.NAMES.get(oid)
                label = (names[0] or names[1] or oid) if names else oid
                keep = [0, 1, 2, 3]
                if tag == 27 and len(data) % 4 == 0:
                    seen = [any(data[j] for j in range(k, len(data), 4)) for k in range(4)]
                    keep = [0, 1, 2, 3] if seen[0] or seen[1] or seen[2] else [3]
                text = bytearray()
                for j, byte in enumerate(data):
                    if j & 3 not in keep:
                        continue
                    text += b"\\x%02X" % byte if byte < 0x20 or byte > 0x7E else bytes([byte])
                piece = b"/" + label.encode() + b"=" + bytes(text)
                if len(out) + len(piece) > X500.ONE_LINE_MAX:
                    return bytes(out)
                out += piece
        return bytes(out)


@dataclass(slots=True)
class Certificate:
    """One certificate, as OpenSSL 1.1's X509 template reads it."""

    raw: bytes
    version: int
    serial: int
    serial_bytes: bytes
    sig_oid: str
    issuer: X500
    subject: X500
    not_before: Tlv
    not_after: Tlv
    spki: Tlv
    subject_key_id: bytes | None = None
    authority_key_id: tuple[bytes | None, X500 | None, int | None] | None = None
    key_usage: int | None = None
    broken: bool = False

    @staticmethod
    def parse(node: Tlv) -> Certificate:
        tbs, sig_alg, signature = node.row(3)
        if not signature.is_tag(3):
            raise BadDer("a certificate signature that is not a BIT STRING")
        fields = tbs.row()
        at = 0
        version = 0
        if fields and fields[0].is_context(0) and fields[0].constructed:
            (inner,) = fields[0].unpack()
            version = inner.whole_number()
            at = 1
        if len(fields) < at + 6:
            raise BadDer("a certificate missing a field")
        serial_node = fields[at].insist(2, constructed=False)
        serial = serial_node.whole_number()
        Tlv._alg_oid(fields[at + 1])
        issuer = X500.parse(fields[at + 2])
        validity = fields[at + 3].row(2)
        for moment in validity:
            if moment.constructed or not (moment.is_tag(23) or moment.is_tag(24)):
                raise BadDer("a validity that is not a time")
        subject = X500.parse(fields[at + 4])
        spki = fields[at + 5]
        key_parts = spki.row(2)
        Tlv._alg_oid(key_parts[0])
        if not key_parts[1].is_tag(3):
            raise BadDer("a public key that is not a BIT STRING")
        cert =Certificate (node .span ,version ,serial ,serial_node .body ,Tlv ._alg_oid (sig_alg ),issuer ,
        subject ,validity [0 ],validity [1 ],spki )  # fmt: skip
        rest = fields[at + 6 :]
        for tag in (1, 2):
            if rest and rest[0].is_context(tag):
                rest = rest[1:]
        if rest and rest[0].is_context(3):
            (holder,) = rest[0].unpack()
            cert._read_extensions(holder.row())
            rest = rest[1:]
        if rest:
            raise BadDer("a certificate with fields out of place")
        return cert

    def _read_extensions(self, exts: list[Tlv]) -> None:
        seen: dict[str, list[bytes]] = {}
        for ext in exts:
            parts = ext.row((2, 3))
            oid = parts[0].object_id()
            if len(parts) == 3 and not parts[1].is_tag(1):
                raise BadDer("an extension's critical flag that is not a BOOLEAN")
            seen.setdefault(oid, []).append(parts[-1].bytes_of())
        readers =(("2.5.29.14",self ._read_skid ),("2.5.29.35",self ._read_akid ),
        ("2.5.29.15",self ._read_usage ))  # fmt: skip
        for oid, reader in readers:
            values = seen.get(oid)
            if values is None:
                continue
            try:
                if len(values) != 1:
                    raise BadDer("an extension twice")
                reader(Tlv.decode(values[0]))
            except (BadDer, ValueError, IndexError):
                self.broken = True
        if "2.5.29.19" in seen:
            try:
                if len(seen["2.5.29.19"]) != 1:
                    raise BadDer("an extension twice")
                Tlv.decode(seen["2.5.29.19"][0]).row((0, 2))
            except (BadDer, ValueError, IndexError):
                self.broken = True

    def _read_skid(self, node: Tlv) -> None:
        self.subject_key_id = node.bytes_of()

    def _read_akid(self, node: Tlv) -> None:
        keyid: bytes | None = None
        issuer: X500 | None = None
        serial: int | None = None
        for part in node.row((0, 3)):
            if part.is_context(0):
                keyid = part.joined()
            elif part.is_context(1):
                for general in part.unpack():
                    if general.is_context(4) and general.constructed and issuer is None:
                        issuer = X500.parse(general.unpack()[0])
            elif part.is_context(2):
                serial = Tlv.number_from(part.body)
        self.authority_key_id = (keyid, issuer, serial)

    def _read_usage(self, node: Tlv) -> None:
        if not node.is_tag(3):
            raise BadDer("a key usage that is not a BIT STRING")
        content = node.joined()
        bits = bytearray(content[1:])
        if bits:
            bits[-1] &= (0xFF << (content[0] & 7)) & 0xFF
        self.key_usage = (bits[0] if bits else 0) | ((bits[1] << 8) if len(bits) > 1 else 0)

    def fields(self) -> dict[str, Any]:
        """The values ``pe.signatures[].certificates`` reports for this certificate."""
        serial: Any = None
        if 1 <= len(self.serial_bytes) <= 20:
            serial = ":".join(f"{b:02x}" for b in self.serial_bytes).encode()
        names = ObjectIds.NAMES.get(self.sig_oid)
        return {
            "thumbprint": hashlib.sha1(self.raw).hexdigest().encode(),  # noqa: S324 - the thumbprint is a SHA-1 digest
            "issuer": self.issuer.one_line(),
            "subject": self.subject.one_line(),
            "version": self.version + 1,
            "algorithm": ((names[1] or "undefined") if names else "undefined").encode(),
            "algorithm_oid": (self.sig_oid if names else "").encode(),
            "serial": serial,
            "not_before": Clock.at_or_fallback(self.not_before),
            "not_after": Clock.at_or_fallback(self.not_after),
        }

        # -- chain building (OpenSSL 1.1's X509_check_issued / build_chain) -------

    def can_issue(self) -> bool:
        return self.key_usage is None or bool(self.key_usage & 0x0004)

    def issues(self, subject: Certificate) -> bool:
        # the issuer test rejects the pair outright if either certificate's extensions did not decode
        # cleanly (OpenSSL's EXFLAG_INVALID), even when the certificate body itself parsed
        return (
            not self.broken
            and not subject.broken
            and self.subject.key == subject.issuer.key
            and subject.authority_matches_of(self)
            and self.can_issue()
            and self._key_loadable()
        )

    def _key_loadable(self) -> bool:
        # chain building ends at a candidate issuer whose public key cannot be loaded: an unknown SPKI
        # algorithm means the issuer's signature over the subject could never be checked, so OpenSSL does
        # not extend the chain through it. This is key loadability, not a signature-algorithm/key-type
        # match (which 1.1 does not do): the key's own algorithm must be one we can read.
        try:
            oid = self.spki.row(2)[0].row((1, 2))[0].object_id()
        except (BadDer, ValueError, IndexError):
            return False
        return oid in (PublicKey.RSA, PublicKey.EC, PublicKey.DSA)

    def authority_matches_of(self, issuer: Certificate) -> bool:
        akid = self.authority_key_id
        if akid is None:
            return True
        keyid, name, serial = akid
        if (
            keyid is not None
            and issuer.subject_key_id is not None
            and keyid != issuer.subject_key_id
        ):
            return False
        if serial is not None and serial != issuer.serial:
            return False
        return not (name is not None and name.key != issuer.issuer.key)

    def is_self_signed(self) -> bool:
        return not self.broken and self.issues(self)

    def valid_at(self, when: int) -> bool:
        before, after = Clock.seconds(self.not_before), Clock.seconds(self.not_after)
        return before is not None and after is not None and before <= when <= after


class ChainWalk:
    """The chain ``X509_verify_cert`` builds from a signer with an empty store (OpenSSL 1.1's
    ``build_chain``): each issuer found among the bundled certificates, preferring one valid now,
    until a self-signed certificate or none is found."""

    LIMIT: ClassVar[int] = 101

    @staticmethod
    def build(signer: Certificate, pool: list[Certificate], when: int) -> list[Certificate]:
        chain = [signer]
        remaining = list(pool)
        topped = signer.is_self_signed()
        while not topped and len(chain) < ChainWalk.LIMIT:
            last = chain[-1]
            found: Certificate | None = None
            for candidate in remaining:
                if candidate is last:
                    accepts = last.is_self_signed()
                else:
                    accepts = candidate.issues(last) and not any(
                        c.raw == candidate.raw for c in chain
                    )
                if accepts:
                    found = candidate
                    if candidate.valid_at(when):
                        break
            if found is None:
                break
            remaining.remove(found)
            chain.append(found)
            topped = found.is_self_signed()
        return chain


class PublicKey:
    """``EVP_VerifyFinal`` / ``EVP_PKEY_verify_recover`` with a certificate's key."""

    RSA: ClassVar[str] = "1.2.840.113549.1.1.1"
    EC: ClassVar[str] = "1.2.840.10045.2.1"
    DSA: ClassVar[str] = "1.2.840.10040.4.1"

    @staticmethod
    def _rsa_params(spki: Tlv) -> tuple[int, int] | None:
        algorithm, key = spki.row(2)
        if algorithm.row((1, 2))[0].object_id() != PublicKey.RSA:
            return None
        bits = key.joined()
        if not bits or bits[0]:
            return None
        modulus, exponent = Tlv.decode(bits[1:]).row(2)
        n, e = modulus.whole_number(), exponent.whole_number()
        if n <= 0 or e <= 0 or n.bit_length() > 16384 or n <= e:
            return None
        if n.bit_length() > 3072 and e.bit_length() > 64:
            return None
        return n, e

    @staticmethod
    def rsa_recover(spki: Tlv, signature: bytes, *, exact: bool) -> bytes | None:
        """RSA public decryption with PKCS #1 type-1 padding removed; None where OpenSSL fails.
        ``exact`` is ``RSA_verify``'s demand that the signature be as long as the modulus."""
        try:
            key = PublicKey._rsa_params(spki)
        except (BadDer, ValueError, IndexError):
            return None
        if key is None:
            return None
        n, e = key
        width = (n.bit_length() + 7) // 8
        if len(signature) > width or (exact and len(signature) != width):
            return None
        s = int(Cursor(signature).uint(0, len(signature), "big"))
        if s >= n:
            return None
        block = pow(s, e, n).to_bytes(width, "big")
        if width < 11 or block[0] != 0 or block[1] != 1:
            return None
        at = 2
        while at < width and block[at] == 0xFF:
            at += 1
        if at == width or block[at] != 0 or at - 2 < 8:
            return None
        return block[at + 1 :]

    @staticmethod
    def verifies(spki: Tlv, digest_name: str, digest: bytes, signature: bytes) -> bool:
        """Whether ``signature`` signs ``digest`` under the key: RSA PKCS #1 v1.5, ECDSA or DSA."""
        try:
            algorithm = spki.row(2)[0].row((1, 2))
            oid = algorithm[0].object_id()
            if oid == PublicKey.RSA:
                if digest_name not in Hash.RSA:
                    return False
                recovered = PublicKey.rsa_recover(spki, signature, exact=True)
                expected = Encode.pkcs1_wrap(digest_name, digest)
                return recovered is not None and expected is not None and recovered == expected
            if oid == PublicKey.EC:
                key = Ecdsa.public_key(PublicKey._strict_der(spki.span))
                parts = Tlv.decode(signature)
                if parts.span != signature:
                    return False
                r, s = (p.whole_number() for p in parts.row(2))
                rebuilt = Encode.wrap(
                    0x30,
                    Encode.wrap(2, PublicKey._der_int(r)) + Encode.wrap(2, PublicKey._der_int(s)),
                )
                if rebuilt != signature:
                    return False
                return Ecdsa.verify_digest(key, digest, r, s)
            if oid == PublicKey.DSA:
                p, q, g = (x.whole_number() for x in algorithm[1].row(3))
                y = Tlv.decode(spki.row(2)[1].joined()[1:]).whole_number()
                rs = Tlv.decode(signature).row(2)
                return Dsa.verify_digest(
                    Dsa.checked(p, q, g, y), digest, rs[0].whole_number(), rs[1].whole_number()
                )
        except (BadDer, ValueError, IndexError, TypeError):
            return False
        return False

    @staticmethod
    def _der_int(value: int) -> bytes:
        return value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True)

    @staticmethod
    def _strict_der(raw: bytes) -> bytes:
        """The key info re-encoded in DER, which the strict EC reader takes."""
        node = Tlv.decode(raw)
        if not node.constructed:
            return Encode.wrap(node.span[0], node.joined())
        return Encode.wrap(
            node.span[0], b"".join(PublicKey._strict_der(c.span) for c in node.unpack())
        )


__all__ = ["X500", "Certificate", "ChainWalk", "PublicKey"]
