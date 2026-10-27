"""YARA's `pe.signatures`: a file's Authenticode signatures, read as YARA 4.5.1 reads them.

YARA describes signatures through its authenticode parser (libyara/modules/pe/authenticode-parser,
Avast, MIT licence) running on OpenSSL 1.1: the PKCS #7 SignedData in the certificate table, the
signatures nested in it, their timestamp countersignatures (PKCS #9 and Microsoft's), each
certificate as OpenSSL formats it, the chain OpenSSL builds from the signer when it has no trust
anchors, and whether each signature verifies over the file. This module is that reader, on
Cordon's own primitives (`intel/provenance`: RSA, ECDSA, DSA): no OpenSSL, no third-party code.

It is as lenient as OpenSSL is and no more: BER (indefinite and long-form lengths, constructed
strings), version 1 certificates and keys of any size are read; what OpenSSL's templates refuse
-- a non-minimal integer, a field out of place, a name holding a value no string type allows --
is refused the same way, with the same effect on what the rule sees. `verified` says the
signature signs the bytes the file carries; it is not trust, and no root is consulted, as in YARA.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_values import UNDEF_INT, UNDEF_STR, Array, Struct, Values
from cordon_scanner.detect.binary.yara_oids import Oids
from cordon_scanner.intel.provenance._dsa import Dsa
from cordon_scanner.intel.provenance._ecdsa import Ecdsa


class AsnError(ValueError):
    """The bytes are not what OpenSSL would decode."""


class Ber:
    """One BER TLV, read as OpenSSL's decoder reads it."""

    __slots__ = ("body", "cls", "cons", "depth", "indefinite", "num", "parts", "raw")

    MAX_DEPTH: ClassVar[int] = 64
    UNIVERSAL: ClassVar[int] = 0
    CONTEXT: ClassVar[int] = 2

    def __init__(self, cls: int, cons: bool, num: int, raw: bytes, body: bytes, depth: int) -> None:
        self.cls, self.cons, self.num, self.raw, self.body, self.depth = (
            cls,
            cons,
            num,
            raw,
            body,
            depth,
        )
        self.parts: list[Ber] | None = None
        self.indefinite = False

    @staticmethod
    def read(data: bytes, at: int = 0, depth: int = 0) -> tuple[Ber, int]:
        if depth > Ber.MAX_DEPTH:
            raise AsnError("nested too deeply")
        n = len(data)
        start = at
        if at >= n:
            raise AsnError("truncated")
        first = data[at]
        at += 1
        cls, cons, num = first >> 6, bool(first & 0x20), first & 0x1F
        if num == 0x1F:
            num = 0
            while True:
                if at >= n or num >> 28:
                    raise AsnError("a tag out of range")
                byte = data[at]
                at += 1
                num = (num << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break
        if at >= n:
            raise AsnError("truncated")
        lb = data[at]
        at += 1
        if lb == 0x80:
            if not cons:
                raise AsnError("an indefinite length on a primitive")
            parts: list[Ber] = []
            body_start = at
            while True:
                if at + 2 > n:
                    raise AsnError("no end of contents")
                if data[at] == 0 and data[at + 1] == 0:
                    body = data[body_start:at]
                    at += 2
                    break
                child, at = Ber.read(data, at, depth + 1)
                parts.append(child)
            node = Ber(cls, cons, num, data[start:at], body, depth)
            node.parts, node.indefinite = parts, True
            return node, at
        if lb & 0x80:
            count = lb & 0x7F
            if count > 8 or at + count > n:
                raise AsnError("a length out of range")
            length = int.from_bytes(data[at : at + count], "big")
            at += count
        else:
            length = lb
        end = at + length
        if end > n:
            raise AsnError("a value past the end")
        return Ber(cls, cons, num, data[start:end], data[at:end], depth), end

    @staticmethod
    def parse(data: bytes) -> Ber:
        """The first TLV in `data`; what follows it is ignored, as `d2i` ignores it."""
        return Ber.read(data)[0]

    def children(self) -> list[Ber]:
        if not self.cons:
            raise AsnError("not constructed")
        if self.parts is None:
            out, at = [], 0
            while at < len(self.body):
                child, at = Ber.read(self.body, at, self.depth + 1)
                out.append(child)
            self.parts = out
        return self.parts

    def universal(self, num: int) -> bool:
        return self.cls == Ber.UNIVERSAL and self.num == num

    def context(self, num: int) -> bool:
        return self.cls == Ber.CONTEXT and self.num == num

    def expect(self, num: int, *, cons: bool | None = None) -> Ber:
        if not self.universal(num) or (cons is not None and self.cons != cons):
            raise AsnError(f"expected universal tag {num}")
        return self

    def content(self) -> bytes:
        """A string's bytes; a constructed string is its pieces joined (`asn1_collect`)."""
        if not self.cons:
            return self.body
        return b"".join(child.content() for child in self.children())

    def integer(self) -> int:
        if not self.universal(2) or self.cons:
            raise AsnError("not an INTEGER")
        return Ber.integer_of(self.body)

    @staticmethod
    def integer_of(b: bytes) -> int:
        """OpenSSL 1.1's `c2i_ibuf`: no empty content, and no padding octet."""
        if not b:
            raise AsnError("an empty integer")
        if len(b) > 1 and (
            (b[0] == 0 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80 and any(b[1:]))
        ):
            raise AsnError("an integer with padding")
        return int.from_bytes(b, "big", signed=True)

    def oid(self) -> str:
        if not self.universal(6) or self.cons:
            raise AsnError("not an OBJECT IDENTIFIER")
        b = self.body
        if not b or b[-1] & 0x80:
            raise AsnError("a malformed object identifier")
        parts: list[int] = []
        value = 0
        for i, byte in enumerate(b):
            if byte == 0x80 and (i == 0 or not b[i - 1] & 0x80):
                raise AsnError("an object identifier arc with a leading zero")
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(value)
                value = 0
        first = parts[0]
        head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
        return ".".join(map(str, head + parts[1:]))

    def octets(self) -> bytes:
        if not self.universal(4):
            raise AsnError("not an OCTET STRING")
        return self.content()

    def sequence(self, count: tuple[int, int] | int | None = None) -> list[Ber]:
        if not self.universal(16) or not self.cons:
            raise AsnError("not a SEQUENCE")
        out = self.children()
        lo, hi = (count, count) if isinstance(count, int) else count or (0, 1 << 30)
        if not lo <= len(out) <= hi:
            raise AsnError("a SEQUENCE of the wrong length")
        return out

    def set_of(self) -> list[Ber]:
        if not self.cons or not self.universal(17):
            raise AsnError("not a SET")
        return self.children()

    def implicit_set(self, num: int) -> list[Ber]:
        if not self.context(num) or not self.cons:
            raise AsnError("not an implicit SET")
        return self.children()


class Der:
    """The few encodings re-made here, as OpenSSL's `i2d` makes them."""

    @staticmethod
    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        size = (n.bit_length() + 7) // 8
        return bytes([0x80 | size]) + n.to_bytes(size, "big")

    @staticmethod
    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + Der.length(len(body)) + body

    @staticmethod
    def attributes(attrs: list[Ber]) -> bytes:
        """Signed attributes as `PKCS7_ATTR_VERIFY` re-encodes them to check a signature: a SET
        in the order they came, each attribute in DER with its values sorted."""
        return Der.tlv(0x31, b"".join(Der._attribute(a) for a in attrs))

    @staticmethod
    def _attribute(attr: Ber) -> bytes:
        kind, values = attr.children()
        encoded = sorted((Der._any(v) for v in values.children()), key=lambda e: (e, len(e)))
        return Der.tlv(0x30, Der.tlv(0x06, kind.body) + Der.tlv(0x31, b"".join(encoded)))

    @staticmethod
    def _any(value: Ber) -> bytes:
        """An ASN1_TYPE as `i2d` writes it: SEQUENCE, SET and tagged values as they came; a
        universal primitive (a constructed string joined first) in its shortest length."""
        if value.cls != Ber.UNIVERSAL or value.num in (16, 17) or value.num >= 31:
            return value.raw
        return Der.tlv(value.num, value.content())

    @staticmethod
    def digest_info(digest_name: str, digest: bytes) -> bytes | None:
        oid = Digests.oid(digest_name)
        if oid is None:
            return None
        arcs = [int(x) for x in oid.split(".")]
        body = bytearray([arcs[0] * 40 + arcs[1]])
        for arc in arcs[2:]:
            chunk = [arc & 0x7F]
            arc >>= 7
            while arc:
                chunk.append(0x80 | (arc & 0x7F))
                arc >>= 7
            body.extend(reversed(chunk))
        algorithm = Der.tlv(0x30, Der.tlv(0x06, bytes(body)) + b"\x05\x00")
        return Der.tlv(0x30, algorithm + Der.tlv(0x04, digest))


class Digests:
    """OpenSSL 1.1's message digests, by the long name of the identifier that selects one."""

    #: alias -> the digest it names: OpenSSL registers each RSA signature identifier as a name
    #: for its digest (`EVP_add_digest`), so a signer naming `sha256WithRSAEncryption` as its
    #: digest gets SHA-256.
    BASE: ClassVar[dict[str, str]] = {
        "md5WithRSAEncryption": "md5", "sha1WithRSAEncryption": "sha1", "mdc2WithRSA": "mdc2",
        "ripemd160WithRSA": "ripemd160", "md4WithRSAEncryption": "md4",
        "sha224WithRSAEncryption": "sha224", "sha256WithRSAEncryption": "sha256",
        "sha384WithRSAEncryption": "sha384", "sha512WithRSAEncryption": "sha512",
        "sha512-224WithRSAEncryption": "sha512-224", "sha512-256WithRSAEncryption": "sha512-256",
        "RSA-SHA3-224": "sha3-224", "RSA-SHA3-256": "sha3-256", "RSA-SHA3-384": "sha3-384",
        "RSA-SHA3-512": "sha3-512", "sm3WithRSAEncryption": "sm3",
    }  # fmt: skip
    #: OpenSSL's name -> hashlib's
    HASHLIB: ClassVar[dict[str, str]] = {
        "sha512-224": "sha512_224", "sha512-256": "sha512_256", "sha3-224": "sha3_224",
        "sha3-256": "sha3_256", "sha3-384": "sha3_384", "sha3-512": "sha3_512",
        "blake2b512": "blake2b", "blake2s256": "blake2s", "shake128": "shake_128", "shake256": "shake_256",
    }  # fmt: skip
    #: digests RSA PKCS #1 v1.5 signs with in OpenSSL 1.1 (`check_padding_md`)
    RSA: ClassVar[frozenset[str]] = frozenset(
        {"sha1", "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256", "md5", "md4",
         "mdc2", "ripemd160", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}
    )  # fmt: skip
    OID: ClassVar[dict[str, str]] = {}

    @staticmethod
    def oid(name: str) -> str | None:
        """The identifier of a digest, by its long name."""
        if not Digests.OID:
            for oid, (_sn, ln) in Oids.NAMES.items():
                if ln in Oids.DIGEST_SIZES and ln not in Digests.BASE:
                    Digests.OID[ln] = oid
        return Digests.OID.get(name)

    @staticmethod
    def long_name(oid: str) -> str:
        """`OBJ_nid2ln(OBJ_obj2nid(oid))`: "undefined" for an identifier OpenSSL does not know."""
        names = Oids.NAMES.get(oid)
        return (names[1] or "undefined") if names else "undefined"

    @staticmethod
    def base(name: str | None) -> str | None:
        """The digest `EVP_get_digestbyname(name)` gives, or None."""
        if name is None or name not in Oids.DIGEST_SIZES:
            return None
        return Digests.BASE.get(name, name)

    @staticmethod
    def compute(name: str, data: bytes) -> bytes | None:
        """The digest, or None where this Python's hashlib lacks one OpenSSL has."""
        size = Oids.DIGEST_SIZES[name]
        try:
            h = hashlib.new(Digests.HASHLIB.get(name, name), data)
        except ValueError:
            return None
        return h.digest(size) if name.startswith("shake") else h.digest()  # type: ignore[call-arg]


class Asn1Time:
    """OpenSSL 1.1's `ASN1_TIME_to_tm` then `timegm`, as the parser turns a time into seconds."""

    #: `timegm` of the zeroed `struct tm` the parser falls back to when a time does not parse:
    #: day 0 of January 1900
    ZERO: ClassVar[int] = -2209075200
    MIN: ClassVar[tuple[int, ...]] = (0, 0, 1, 1, 0, 0, 0, 0, 0)
    MAX: ClassVar[tuple[int, ...]] = (99, 99, 12, 31, 23, 59, 59, 12, 59)
    DAYS: ClassVar[tuple[int, ...]] = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

    @staticmethod
    def seconds(node: Ber | None) -> int | None:
        """Seconds since the epoch, or None when OpenSSL could not read the time."""
        if node is None or node.cons or not (node.universal(23) or node.universal(24)):
            return None
        utc = node.universal(23)
        a = node.body
        end, btz, min_l = (6, 5, 11) if utc else (7, 6, 13)
        n = len(a)
        if n < min_l:
            return None
        year = mon = mday = hour = minute = sec = 0
        o = 0
        i = 0
        while i < end:
            if i == btz and o < n and a[o] in b"Z+-":
                break
            if o + 1 >= n or not (0x30 <= a[o] <= 0x39 and 0x30 <= a[o + 1] <= 0x39):
                return None
            v = (a[o] - 0x30) * 10 + a[o + 1] - 0x30
            o += 2
            if o == n:
                return None
            i2 = i + 1 if utc else i
            if not Asn1Time.MIN[i2] <= v <= Asn1Time.MAX[i2]:
                return None
            if i2 == 0:
                year = v * 100
            elif i2 == 1:
                year = (2000 + v if v < 50 else 1900 + v) if utc else year + v
            elif i2 == 2:
                mon = v
            elif i2 == 3:
                leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
                if v > Asn1Time.DAYS[mon - 1] + (1 if mon == 2 and leap else 0):
                    return None
                mday = v
            elif i2 == 4:
                hour = v
            elif i2 == 5:
                minute = v
            else:
                sec = v
            i += 1
        if not utc and o < n and a[o] == 0x2E:
            o += 1
            if o == n:
                return None
            start = o
            while o < n and 0x30 <= a[o] <= 0x39:
                o += 1
            if o in (start, n):
                return None
        offset = 0
        if o < n and a[o] == 0x5A:
            o += 1
        elif o < n and a[o] in b"+-":
            sign = 1 if a[o] == 0x2D else -1
            o += 1
            if o + 4 != n:
                return None
            for k in range(2):
                if not (0x30 <= a[o] <= 0x39 and 0x30 <= a[o + 1] <= 0x39):
                    return None
                v = (a[o] - 0x30) * 10 + a[o + 1] - 0x30
                if (
                    not Asn1Time.MIN[end + k + (1 if utc else 0)]
                    <= v
                    <= Asn1Time.MAX[end + k + (1 if utc else 0)]
                ):
                    return None
                offset += v * 3600 if k == 0 else v * 60
                o += 2
            offset *= sign
        else:
            return None
        if o != n:
            return None
        return Asn1Time.timegm(year, mon, mday, hour, minute, sec) + offset

    @staticmethod
    def timegm(year: int, mon: int, mday: int, hour: int, minute: int, sec: int) -> int:
        """`timegm` over the proleptic Gregorian calendar, any year (days from civil)."""
        y = year - (mon <= 2)
        era = y // 400
        yoe = y - era * 400
        doy = (153 * (mon + (-3 if mon > 2 else 9)) + 2) // 5 + mday - 1
        days = era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719468
        return days * 86400 + hour * 3600 + minute * 60 + sec

    @staticmethod
    def or_zero(node: Ber | None) -> int:
        value = Asn1Time.seconds(node)
        return Asn1Time.ZERO if value is None else value


class Name:
    """An X.509 Name: its entries in order, OpenSSL's one-line form and its comparison key."""

    #: universal tags an entry's value may carry (`B_ASN1_PRINTABLE`); any other fails the parse
    ALLOWED: ClassVar[frozenset[int]] = frozenset(
        {18, 19, 20, 22, 3, 28, 30, 12, 16, 7, 8, 9, 10, 11, 13, 14, 15, 29}
    )
    #: tags whose values are compared case- and space-folded (`ASN1_MASK_CANON`)
    CANON: ClassVar[frozenset[int]] = frozenset({12, 30, 28, 19, 20, 22, 26})
    ONELINE_MAX: ClassVar[int] = 255

    def __init__(self, raw: bytes, rdns: list[list[tuple[str, int, bytes]]]) -> None:
        self.raw, self.rdns = raw, rdns
        self.key = tuple(tuple(sorted(Name._canon(e) for e in rdn)) for rdn in rdns if rdn)

    @staticmethod
    def parse(node: Ber) -> Name:
        rdns: list[list[tuple[str, int, bytes]]] = []
        for rdn in node.sequence():
            entries = []
            for entry in rdn.set_of():
                parts = entry.sequence(2)
                oid = parts[0].oid()
                value = parts[1]
                if value.cls != Ber.UNIVERSAL or value.num not in Name.ALLOWED:
                    raise AsnError("a name value of a type OpenSSL does not allow")
                if value.num == 16:
                    data = value.raw
                elif value.num == 3:
                    content = value.content()
                    data = content[1:] if content else b""
                else:
                    data = value.content()
                entries.append((oid, value.num, data))
            rdns.append(entries)
        return Name(node.raw, rdns)

    @staticmethod
    def _canon(entry: tuple[str, int, bytes]) -> tuple[str, int, bytes]:
        oid, tag, data = entry
        if tag not in Name.CANON:
            return oid, tag, data
        try:
            if tag == 12:
                text = data.decode("utf-8")
            elif tag == 30:
                if len(data) % 2:
                    raise AsnError("a BMPString of odd length")
                text = data.decode("utf-16-be", "surrogatepass")
            elif tag == 28:
                if len(data) % 4:
                    raise AsnError("a UniversalString of the wrong length")
                text = data.decode("utf-32-be")
            else:
                text = data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise AsnError("a name value not in its encoding") from exc
        utf8 = text.encode("utf-8", "surrogatepass")
        spaces = b" \t\n\v\f\r"
        utf8 = utf8.strip(spaces)
        out = bytearray()
        i = 0
        while i < len(utf8):
            c = utf8[i]
            if c >= 0x80:
                out.append(c)
                i += 1
            elif c in spaces:
                out.append(0x20)
                while i < len(utf8) and utf8[i] in spaces:
                    i += 1
            else:
                out.append(c + 32 if 0x41 <= c <= 0x5A else c)
                i += 1
        return oid, 12, bytes(out)

    def oneline(self) -> bytes:
        """`X509_NAME_oneline` into the parser's 256-byte buffer: `/C=US/O=...`, a byte outside
        printable ASCII as `\\xHH`, entries that would not fit left off."""
        out = bytearray()
        for rdn in self.rdns:
            for oid, tag, data in rdn:
                names = Oids.NAMES.get(oid)
                key = (names[0] or names[1] or oid) if names else oid
                keep = [0, 1, 2, 3]
                if tag == 27 and len(data) % 4 == 0:
                    seen = [any(data[j] for j in range(k, len(data), 4)) for k in range(4)]
                    keep = [0, 1, 2, 3] if seen[0] or seen[1] or seen[2] else [3]
                text = bytearray()
                for j, byte in enumerate(data):
                    if j & 3 not in keep:
                        continue
                    text += b"\\x%02X" % byte if byte < 0x20 or byte > 0x7E else bytes([byte])
                piece = b"/" + key.encode() + b"=" + bytes(text)
                if len(out) + len(piece) > Name.ONELINE_MAX:
                    return bytes(out)
                out += piece
        return bytes(out)


@dataclass
class Cert:
    """One certificate, as OpenSSL 1.1's X509 template reads it."""

    raw: bytes
    version: int
    serial: int
    serial_bytes: bytes
    sig_oid: str
    issuer: Name
    subject: Name
    not_before: Ber
    not_after: Ber
    spki: Ber
    skid: bytes | None = None
    akid: tuple[bytes | None, Name | None, int | None] | None = None
    key_usage: int | None = None
    invalid: bool = False

    @staticmethod
    def parse(node: Ber) -> Cert:
        tbs, sig_alg, signature = node.sequence(3)
        if not signature.universal(3):
            raise AsnError("a certificate signature that is not a BIT STRING")
        fields = tbs.sequence()
        at = 0
        version = 0
        if fields and fields[0].context(0) and fields[0].cons:
            (inner,) = fields[0].children()
            version = inner.integer()
            at = 1
        if len(fields) < at + 6:
            raise AsnError("a certificate missing a field")
        serial_node = fields[at].expect(2, cons=False)
        serial = serial_node.integer()
        Cert._algorithm(fields[at + 1])
        issuer = Name.parse(fields[at + 2])
        validity = fields[at + 3].sequence(2)
        for t in validity:
            if t.cons or not (t.universal(23) or t.universal(24)):
                raise AsnError("a validity that is not a time")
        subject = Name.parse(fields[at + 4])
        spki = fields[at + 5]
        key_parts = spki.sequence(2)
        Cert._algorithm(key_parts[0])
        if not key_parts[1].universal(3):
            raise AsnError("a public key that is not a BIT STRING")
        cert = Cert(node.raw, version, serial, serial_node.body, Cert._algorithm(sig_alg), issuer,
                    subject, validity[0], validity[1], spki)  # fmt: skip
        rest = fields[at + 6 :]
        for tag in (1, 2):
            if rest and rest[0].context(tag):
                rest = rest[1:]
        if rest and rest[0].context(3):
            (exts,) = rest[0].children()
            cert._extensions(exts.sequence())
            rest = rest[1:]
        if rest:
            raise AsnError("a certificate with fields out of place")
        return cert

    @staticmethod
    def _algorithm(node: Ber) -> str:
        parts = node.sequence((1, 2))
        return parts[0].oid()

    def _extensions(self, exts: list[Ber]) -> None:
        seen: dict[str, list[bytes]] = {}
        for ext in exts:
            parts = ext.sequence((2, 3))
            oid = parts[0].oid()
            if len(parts) == 3 and not parts[1].universal(1):
                raise AsnError("an extension's critical flag that is not a BOOLEAN")
            seen.setdefault(oid, []).append(parts[-1].octets())
        for oid, attr in (("2.5.29.14", "skid"), ("2.5.29.35", "akid"), ("2.5.29.15", "key_usage")):
            values = seen.get(oid)
            if values is None:
                continue
            try:
                if len(values) != 1:
                    raise AsnError("an extension twice")
                setattr(self, attr, getattr(Cert, "_" + attr)(Ber.parse(values[0])))
            except (AsnError, ValueError, IndexError):
                self.invalid = True
        if "2.5.29.19" in seen:
            try:
                if len(seen["2.5.29.19"]) != 1:
                    raise AsnError("an extension twice")
                Ber.parse(seen["2.5.29.19"][0]).sequence((0, 2))
            except (AsnError, ValueError, IndexError):
                self.invalid = True

    @staticmethod
    def _skid(node: Ber) -> bytes:
        return node.octets()

    @staticmethod
    def _akid(node: Ber) -> tuple[bytes | None, Name | None, int | None]:
        keyid: bytes | None = None
        issuer: Name | None = None
        serial: int | None = None
        for part in node.sequence((0, 3)):
            if part.context(0):
                keyid = part.content()
            elif part.context(1):
                for general in part.children():
                    if general.context(4) and general.cons and issuer is None:
                        issuer = Name.parse(general.children()[0])
            elif part.context(2):
                serial = Ber.integer_of(part.body)
        return keyid, issuer, serial

    @staticmethod
    def _key_usage(node: Ber) -> int:
        if not node.universal(3):
            raise AsnError("a key usage that is not a BIT STRING")
        content = node.content()
        bits = bytearray(content[1:])
        if bits:
            bits[-1] &= (0xFF << (content[0] & 7)) & 0xFF
        return (bits[0] if bits else 0) | ((bits[1] << 8) if len(bits) > 1 else 0)

    # -- what the rule sees --------------------------------------------------

    def fields(self) -> dict[str, Any]:
        serial: Any = UNDEF_STR
        if 1 <= len(self.serial_bytes) <= 20:
            serial = ":".join(f"{b:02x}" for b in self.serial_bytes).encode()
        names = Oids.NAMES.get(self.sig_oid)
        return {
            "thumbprint": hashlib.sha1(self.raw).hexdigest().encode(),  # noqa: S324 - YARA's thumbprint is SHA-1
            "issuer": self.issuer.oneline(),
            "subject": self.subject.oneline(),
            "version": self.version + 1,
            "algorithm": ((names[1] or "undefined") if names else "undefined").encode(),
            "algorithm_oid": (self.sig_oid if names else "").encode(),
            "serial": serial,
            "not_before": Asn1Time.or_zero(self.not_before),
            "not_after": Asn1Time.or_zero(self.not_after),
        }

    # -- chain building (OpenSSL 1.1's `X509_check_issued`) -------------------

    def akid_matches(self, akid: tuple[bytes | None, Name | None, int | None] | None) -> bool:
        if akid is None:
            return True
        keyid, issuer, serial = akid
        if keyid is not None and self.skid is not None and keyid != self.skid:
            return False
        if serial is not None and serial != self.serial:
            return False
        return not (issuer is not None and issuer.key != self.issuer.key)

    def may_sign_certificates(self) -> bool:
        return self.key_usage is None or bool(self.key_usage & 0x0004)

    def issued(self, subject: Cert) -> bool:
        return (
            self.subject.key == subject.issuer.key
            and self.akid_matches(subject.akid)
            and self.may_sign_certificates()
        )

    def self_signed(self) -> bool:
        return not self.invalid and self.issued(self)

    def valid_now(self, now: int) -> bool:
        nb, na = Asn1Time.seconds(self.not_before), Asn1Time.seconds(self.not_after)
        return nb is not None and na is not None and nb <= now <= na


class Chain:
    """The chain `X509_verify_cert` builds from a signer with an empty store (OpenSSL 1.1's
    `build_chain`): each issuer found among the bundled certificates, preferring one valid now,
    until a self-signed certificate or none is found."""

    MAX: ClassVar[int] = 101

    @staticmethod
    def build(signer: Cert, certs: list[Cert], now: int) -> list[Cert]:
        chain = [signer]
        pool = list(certs)
        top_self_signed = signer.self_signed()
        while not top_self_signed and len(chain) < Chain.MAX:
            last = chain[-1]
            found: Cert | None = None
            for candidate in pool:
                if candidate is last:
                    ok = last.self_signed()
                else:
                    ok = candidate.issued(last) and not any(c.raw == candidate.raw for c in chain)
                if ok:
                    found = candidate
                    if candidate.valid_now(now):
                        break
            if found is None:
                break
            pool.remove(found)
            chain.append(found)
            top_self_signed = found.self_signed()
        return chain


class Keys:
    """`EVP_VerifyFinal` and `EVP_PKEY_verify_recover` with a certificate's key."""

    RSA: ClassVar[str] = "1.2.840.113549.1.1.1"
    EC: ClassVar[str] = "1.2.840.10045.2.1"
    DSA: ClassVar[str] = "1.2.840.10040.4.1"

    @staticmethod
    def _rsa(spki: Ber) -> tuple[int, int] | None:
        algorithm, key = spki.sequence(2)
        if algorithm.sequence((1, 2))[0].oid() != Keys.RSA:
            return None
        bits = key.content()
        if not bits or bits[0]:
            return None
        n_node, e_node = Ber.parse(bits[1:]).sequence(2)
        n, e = n_node.integer(), e_node.integer()
        if n <= 0 or e <= 0 or n.bit_length() > 16384 or n <= e:
            return None
        if n.bit_length() > 3072 and e.bit_length() > 64:
            return None
        return n, e

    @staticmethod
    def recover(spki: Ber, signature: bytes, *, exact: bool) -> bytes | None:
        """RSA public decryption with PKCS #1 type 1 padding removed; None where OpenSSL fails.
        `exact` is `RSA_verify`'s demand that the signature be as long as the modulus."""
        try:
            key = Keys._rsa(spki)
        except (AsnError, ValueError, IndexError):
            return None
        if key is None:
            return None
        n, e = key
        k = (n.bit_length() + 7) // 8
        if len(signature) > k or (exact and len(signature) != k):
            return None
        s = int.from_bytes(signature, "big")
        if s >= n:
            return None
        em = pow(s, e, n).to_bytes(k, "big")
        if k < 11 or em[0] != 0 or em[1] != 1:
            return None
        at = 2
        while at < k and em[at] == 0xFF:
            at += 1
        if at == k or em[at] != 0 or at - 2 < 8:
            return None
        return em[at + 1 :]

    @staticmethod
    def verify(spki: Ber, digest_name: str, digest: bytes, signature: bytes) -> bool:
        """Whether `signature` signs `digest` under the key: RSA PKCS #1 v1.5, ECDSA or DSA."""
        try:
            algorithm = spki.sequence(2)[0].sequence((1, 2))
            oid = algorithm[0].oid()
            if oid == Keys.RSA:
                if digest_name not in Digests.RSA:
                    return False
                recovered = Keys.recover(spki, signature, exact=True)
                expected = Der.digest_info(digest_name, digest)
                return recovered is not None and expected is not None and recovered == expected
            if oid == Keys.EC:
                key = Ecdsa.public_key(Keys._der(spki.raw))
                parts = Ber.parse(signature)
                if parts.raw != signature:
                    return False
                r, s = (p.integer() for p in parts.sequence(2))
                if Der.tlv(0x30, Der.tlv(2, Keys._int(r)) + Der.tlv(2, Keys._int(s))) != signature:
                    return False
                return Ecdsa.verify_digest(key, digest, r, s)
            if oid == Keys.DSA:
                p, q, g = (x.integer() for x in algorithm[1].sequence(3))
                y = Ber.parse(spki.sequence(2)[1].content()[1:]).integer()
                rs = Ber.parse(signature).sequence(2)
                return Dsa.verify_digest(
                    Dsa.checked(p, q, g, y), digest, rs[0].integer(), rs[1].integer()
                )
        except (AsnError, ValueError, IndexError, TypeError):
            return False
        return False

    @staticmethod
    def _int(value: int) -> bytes:
        return value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True)

    @staticmethod
    def _der(raw: bytes) -> bytes:
        """The key info re-encoded in DER, which the strict EC reader takes."""
        node = Ber.parse(raw)
        if not node.cons:
            return Der.tlv(node.raw[0], node.content())
        return Der.tlv(node.raw[0], b"".join(Keys._der(child.raw) for child in node.children()))


@dataclass
class SignerInfo:
    raw: Ber
    issuer: Name | None
    serial: int | None
    ski: bytes | None
    digest_oid: str
    signed: list[Ber] | None
    signature: bytes
    unsigned: list[Ber] | None

    @staticmethod
    def parse(node: Ber, *, cms: bool) -> SignerInfo:
        parts = node.sequence((5, 7))
        parts[0].integer()
        sid = parts[1]
        issuer: Name | None = None
        serial: int | None = None
        ski: bytes | None = None
        if sid.universal(16):
            name, number = sid.sequence(2)
            issuer, serial = Name.parse(name), number.integer()
        elif cms and sid.context(0) and not sid.cons:
            ski = sid.body
        else:
            raise AsnError("a signer identified by neither issuer and serial nor key")
        digest_oid = Cert._algorithm(parts[2])
        at = 3
        signed: list[Ber] | None = None
        if parts[at].context(0):
            signed = parts[at].implicit_set(0)
            at += 1
        if at + 2 > len(parts):
            raise AsnError("a signer info missing a field")
        Cert._algorithm(parts[at])
        signature = parts[at + 1].octets()
        unsigned: list[Ber] | None = None
        if at + 2 < len(parts):
            unsigned = parts[at + 2].implicit_set(1)
            if at + 3 < len(parts):
                raise AsnError("a signer info with fields out of place")
        for attr in (signed or []) + (unsigned or []):
            attr_parts = attr.sequence(2)
            attr_parts[0].oid()
            attr_parts[1].set_of()
        return SignerInfo(node, issuer, serial, ski, digest_oid, signed, signature, unsigned)

    @staticmethod
    def attribute(attrs: list[Ber] | None, oid: str) -> list[Ber] | None:
        """The values of the first attribute of this type (`X509at_get_attr_by_NID`)."""
        for attr in attrs or []:
            kind, values = attr.children()
            if kind.oid() == oid:
                return values.children()
        return None

    def first(self, oid: str, *, signed: bool) -> Ber | None:
        values = SignerInfo.attribute(self.signed if signed else self.unsigned, oid)
        return values[0] if values else None

    def find(self, certs: list[Cert]) -> Cert | None:
        for cert in certs:
            if self.ski is not None:
                if cert.skid is not None and cert.skid == self.ski:
                    return cert
            elif (
                cert.serial == self.serial
                and self.issuer is not None
                and cert.issuer.key == self.issuer.key
            ):
                return cert
        return None


@dataclass
class SignedData:
    """PKCS #7 (or, for a timestamp, CMS) SignedData."""

    version: int
    digest_oids: list[str]
    content_type: str
    content: Ber | None
    certs: list[Cert]
    signers: list[SignerInfo]

    SIGNED: ClassVar[str] = "1.2.840.113549.1.7.2"

    @staticmethod
    def parse(data: bytes, *, cms: bool = False) -> tuple[str, SignedData | None]:
        """The ContentInfo's type and, when it is SignedData, the SignedData."""
        outer = Ber.parse(data).sequence((1, 2))
        kind = outer[0].oid()
        if kind != SignedData.SIGNED:
            if cms:
                raise AsnError("not SignedData")
            if len(outer) == 2 and not (outer[1].context(0) and outer[1].cons):
                raise AsnError("a content that is not [0]")
            return kind, None
        if len(outer) == 1:
            if cms:
                raise AsnError("SignedData without content")
            return kind, None
        if not (outer[1].context(0) and outer[1].cons):
            raise AsnError("a content that is not [0]")
        (signed,) = outer[1].children()
        parts = signed.sequence((4, 6))
        version = parts[0].integer()
        digest_oids = [Cert._algorithm(a) for a in parts[1].set_of()]
        inner = parts[2].sequence((1, 2))
        content_type = inner[0].oid()
        content: Ber | None = None
        if len(inner) == 2:
            if not (inner[1].context(0) and inner[1].cons):
                raise AsnError("an inner content that is not [0]")
            (content,) = inner[1].children()
            if cms and not content.universal(4):
                raise AsnError("encapsulated content that is not an OCTET STRING")
        at = 3
        certs: list[Cert] = []
        if parts[at].context(0):
            for choice in parts[at].children():
                if choice.universal(16):
                    certs.append(Cert.parse(choice))
                elif not cms:
                    raise AsnError("a certificate choice PKCS #7 does not have")
            at += 1
        if at < len(parts) and parts[at].context(1):
            at += 1
        if at != len(parts) - 1:
            raise AsnError("SignedData with fields out of place")
        signers = [SignerInfo.parse(s, cms=cms) for s in parts[at].set_of()]
        return kind, SignedData(version, digest_oids, content_type, content, certs, signers)

    def digest_names(self) -> list[str] | None:
        """The digests the data is hashed with; None when OpenSSL does not know one of them."""
        names = []
        for oid in self.digest_oids:
            base = Digests.base(Digests.long_name(oid))
            if base is None:
                return None
            names.append(base)
        return names

    def signature_verifies(self, si: SignerInfo, cert: Cert, content: bytes) -> bool:
        """`PKCS7_signatureVerify`: the signed attributes' digest of the content, then the
        signature over those attributes (or, with none, over the content)."""
        names = self.digest_names()
        name = Digests.base(Digests.long_name(si.digest_oid))
        if names is None or name is None or name not in names:
            return False
        digest = Digests.compute(name, content)
        if digest is None:
            return False
        if si.signed:
            claimed = si.first("1.2.840.113549.1.9.4", signed=True)
            if claimed is None or claimed.content() != digest:
                return False
            signed_digest = Digests.compute(name, Der.attributes(si.signed))
            if signed_digest is None:
                return False
            digest = signed_digest
        return Keys.verify(cert.spki, name, digest, si.signature)


@dataclass
class Countersignature:
    verified: bool = False
    sign_time: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    chain: list[Cert] | None = None
    certs: list[Cert] = field(default_factory=list)

    @staticmethod
    def pkcs9(value: Ber, certs: list[Cert], parent_signature: bytes, now: int) -> Countersignature:
        result = Countersignature()
        try:
            si = SignerInfo.parse(value, cms=False)
        except (AsnError, ValueError, IndexError):
            return result
        result.digest_alg = Digests.long_name(si.digest_oid)
        when = si.first("1.2.840.113549.1.9.5", signed=True)
        if when is None:
            return result
        result.sign_time = Asn1Time.or_zero(when)
        cert = si.find(certs)
        if cert is None:
            return result
        result.chain = Chain.build(cert, certs, now)
        claimed = si.first("1.2.840.113549.1.9.4", signed=True)
        claimed_digest = claimed.content() if claimed is not None else b""
        if not claimed_digest:
            return result
        name = Digests.base(result.digest_alg)
        if name is None:
            return result
        result.digest = claimed_digest
        calculated = Digests.compute(name, Der.attributes(si.signed or []))
        recovered = Keys.recover(cert.spki, si.signature, exact=False)
        if calculated is None or recovered is None:
            return result
        size = Oids.DIGEST_SIZES[name]
        if len(recovered) == size:
            valid = recovered == calculated
        else:
            try:
                inner = Ber.parse(recovered).sequence(2)
                valid = inner[1].octets()[:size] == calculated
            except (AsnError, ValueError, IndexError):
                valid = False
        if not valid:
            return result
        expected = Digests.compute(name, parent_signature)
        result.verified = (
            expected is not None and len(claimed_digest) == size and claimed_digest == expected
        )
        return result

    @staticmethod
    def microsoft(value: Ber, parent_signature: bytes, now: int) -> Countersignature:
        result = Countersignature()
        signed: SignedData | None = None
        cms = False
        try:
            signed = SignedData.parse(value.raw)[1]
            if signed is None:
                return result
        except (AsnError, ValueError, IndexError):
            try:
                _, signed = SignedData.parse(value.raw, cms=True)
                cms = True
            except (AsnError, ValueError, IndexError):
                return result
        if signed is None:
            return result
        tst = Countersignature._tst_info(signed)
        if tst is None:
            return result
        tst_version, gen_time, imprint_oid, imprint = tst
        result.sign_time = Asn1Time.or_zero(gen_time)
        cert = Countersignature._signer(signed, cms=cms)
        if cert is None:
            return result
        result.certs = list(signed.certs)
        result.chain = Chain.build(cert, signed.certs, now)
        result.digest_alg = Digests.long_name(imprint_oid)
        result.digest = imprint or None
        if not imprint:
            return result
        name = Digests.base(result.digest_alg)
        if name is None:
            return result
        expected = Digests.compute(name, parent_signature)
        if expected is None or imprint != expected or tst_version != 1:
            return result
        content = (
            signed.content.content()
            if signed.content is not None and signed.content.universal(4)
            else b""
        )
        si = signed.signers[0]
        if cms:
            result.verified = Countersignature._cms_content(signed, si, content)
        else:
            result.verified = signed.signature_verifies(si, cert, content)
        return result

    @staticmethod
    def _tst_info(signed: SignedData) -> tuple[int, Ber | None, str, bytes] | None:
        if signed.content_type != "1.2.840.113549.1.9.16.1.4" or signed.content is None:
            return None
        if not signed.content.universal(4):
            return None
        try:
            parts = Ber.parse(signed.content.content()).sequence((5, 10))
            version = parts[0].integer()
            parts[1].oid()
            imprint_alg, imprint = parts[2].sequence(2)
            oid = Cert._algorithm(imprint_alg)
            digest = imprint.octets()
            parts[3].integer()
            gen_time = parts[4]
            if not gen_time.universal(24):
                return None
        except (AsnError, ValueError, IndexError):
            return None
        return version, gen_time, oid, digest

    @staticmethod
    def _signer(signed: SignedData, *, cms: bool) -> Cert | None:
        if not signed.signers:
            return None
        if cms:
            for si in signed.signers:
                for cert in signed.certs:
                    if (si.ski is not None and cert.skid == si.ski) or (
                        si.ski is None
                        and si.issuer is not None
                        and cert.serial == si.serial
                        and cert.issuer.key == si.issuer.key
                    ):
                        return cert
            return None
        found = [si.find(signed.certs) for si in signed.signers]
        return None if any(c is None for c in found) else found[0]

    @staticmethod
    def _cms_content(signed: SignedData, si: SignerInfo, content: bytes) -> bool:
        """`CMS_SignerInfo_verify_content`: the content's digest against the signed one."""
        names = signed.digest_names()
        name = Digests.base(Digests.long_name(si.digest_oid))
        if names is None or name is None or name not in names or si.signed is None:
            return False
        claimed = [
            v for a in si.signed for k, v in [a.children()] if k.oid() == "1.2.840.113549.1.9.4"
        ]
        if (
            len(claimed) != 1
            or len(claimed[0].children()) != 1
            or not claimed[0].children()[0].universal(4)
        ):
            return False
        digest = Digests.compute(name, content)
        return digest is not None and claimed[0].children()[0].content() == digest


@dataclass
class Signature:
    """One Authenticode signature: `Authenticode` in the parser."""

    flags: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    file_digest: bytes | None = None
    certs: list[Cert] = field(default_factory=list)
    signer: bool = False
    chain: list[Cert] = field(default_factory=list)
    signer_digest_alg: str | None = None
    signer_digest: bytes | None = None
    program_name: bytes | None = None
    countersigs: list[Countersignature] | None = None

    VALID: ClassVar[int] = 0
    CANT_PARSE: ClassVar[int] = 1
    NO_SIGNER_CERT: ClassVar[int] = 2
    DIGEST_MISSING: ClassVar[int] = 3
    INTERNAL_ERROR: ClassVar[int] = 4
    NO_SIGNER_INFO: ClassVar[int] = 5
    WRONG_PKCS7_TYPE: ClassVar[int] = 6
    BAD_CONTENT: ClassVar[int] = 7
    INVALID: ClassVar[int] = 8
    WRONG_FILE_DIGEST: ClassVar[int] = 9
    UNKNOWN_ALGORITHM: ClassVar[int] = 10
    #: the outcomes YARA does not report a signature for
    HIDDEN: ClassVar[frozenset[int]] = frozenset({1, 2, 4, 5, 6})
    MAX_NESTED: ClassVar[int] = 16
    MAX_DEPTH: ClassVar[int] = 32


class Authenticode:
    """`Authenticode.signatures(data)`: what `pe.signatures` holds for a file."""

    INDIRECT_DATA: ClassVar[str] = "1.3.6.1.4.1.311.2.1.4"
    OPUS_INFO: ClassVar[str] = "1.3.6.1.4.1.311.2.1.12"
    NESTED: ClassVar[str] = "1.3.6.1.4.1.311.2.4.1"
    MS_COUNTERSIGNATURE: ClassVar[str] = "1.3.6.1.4.1.311.3.3.1"
    COUNTERSIGNATURE: ClassVar[str] = "1.2.840.113549.1.9.6"
    MESSAGE_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"

    @staticmethod
    def parse(blob: bytes, now: int, depth: int = 0) -> list[Signature]:
        """`authenticode_new`: this signature, then the ones nested in it."""
        if not blob:
            return []
        auth = Signature()
        out = [auth]
        try:
            _, signed = SignedData.parse(blob)
        except (AsnError, ValueError, IndexError):
            auth.flags = Signature.CANT_PARSE
            return out
        if signed is None:
            auth.flags = Signature.WRONG_PKCS7_TYPE
            return out
        auth.certs = list(signed.certs)
        content = Authenticode._indirect(signed)
        if content is None:
            auth.flags = Signature.BAD_CONTENT
            return out
        auth.digest_alg, auth.digest = Digests.long_name(content[0]), content[1]
        auth.signer = True
        if not signed.signers:
            auth.flags = Signature.NO_SIGNER_INFO
            return out
        si = signed.signers[0]
        auth.countersigs = []
        nested = SignerInfo.attribute(si.unsigned, Authenticode.NESTED) or []
        if depth < Signature.MAX_DEPTH:
            for value in nested[: Signature.MAX_NESTED]:
                out.extend(Authenticode.parse(value.raw, now, depth + 1))
        for value in (SignerInfo.attribute(si.unsigned, Authenticode.COUNTERSIGNATURE) or [])[
            : Signature.MAX_NESTED
        ]:
            auth.countersigs.append(Countersignature.pkcs9(value, signed.certs, si.signature, now))
        for value in (SignerInfo.attribute(si.unsigned, Authenticode.MS_COUNTERSIGNATURE) or [])[
            : Signature.MAX_NESTED
        ]:
            counter = Countersignature.microsoft(value, si.signature, now)
            auth.countersigs.append(counter)
            auth.certs.extend(counter.certs)
        signers = [s.find(signed.certs) for s in signed.signers]
        cert = None if any(c is None for c in signers) else signers[0]
        if cert is None:
            auth.flags = Signature.NO_SIGNER_CERT
            return out
        auth.chain = Chain.build(cert, signed.certs, now)
        claimed = si.first(Authenticode.MESSAGE_DIGEST, signed=True)
        if claimed is None:
            auth.flags = Signature.DIGEST_MISSING
            return out
        auth.signer_digest_alg = Digests.long_name(si.digest_oid)
        auth.signer_digest = claimed.content() or None
        opus = si.first(Authenticode.OPUS_INFO, signed=True)
        if opus is not None:
            auth.program_name = Authenticode._program_name(opus)
        inner = signed.content.raw if signed.content is not None else b""
        if signed.version == 1 and signed.content is not None:
            inner = b"" if signed.content.indefinite else signed.content.body
        if not signed.signature_verifies(si, cert, inner):
            auth.flags = Signature.INVALID
        return out

    @staticmethod
    def _indirect(signed: SignedData) -> tuple[str, bytes] | None:
        """SpcIndirectDataContent's digest algorithm and digest."""
        if signed.content_type != Authenticode.INDIRECT_DATA or signed.content is None:
            return None
        try:
            data, digest_info = Ber.parse(signed.content.raw).sequence(2)
            data.sequence((1, 2))[0].oid()
            algorithm, digest = digest_info.sequence(2)
            return Cert._algorithm(algorithm), digest.octets()
        except (AsnError, ValueError, IndexError):
            return None

    @staticmethod
    def _program_name(opus: Ber) -> bytes | None:
        if not opus.universal(16):
            return None
        try:
            for part in opus.sequence((0, 2)):
                if part.context(0) and part.cons:
                    (choice,) = part.children()
                    raw = choice.content()
                    if choice.context(0):
                        if len(raw) % 2:
                            return None
                        name = raw.decode("utf-16-be", "surrogatepass").encode(
                            "utf-8", "surrogatepass"
                        )
                    elif choice.context(1):
                        name = raw.decode("latin-1").encode("utf-8")
                    else:
                        return None
                    return name if len(name) < len(opus.raw) else None
        except (AsnError, ValueError, IndexError, UnicodeDecodeError):
            return None
        return None

    @staticmethod
    def file_digest(
        data: bytes, name: str, pe_offset: int, is64: bool, cert_addr: int
    ) -> bytes | None:
        """The Authenticode digest of the file as the parser takes it: everything before the
        certificate table, less the checksum and the table's own directory entry."""
        checksum_at = pe_offset + 0x58
        directory_at = checksum_at + 4 + 0x3C + (16 if is64 else 0)
        if cert_addr < directory_at + 8:
            return None
        return Digests.compute(
            name,
            data[:checksum_at]
            + data[checksum_at + 4 : directory_at]
            + data[directory_at + 8 : cert_addr],
        )

    @staticmethod
    def signatures(data: bytes) -> list[Signature]:
        """`parse_authenticode`: every signature in the first certificate, with file digests."""
        if len(data) < 0x40 or data[:2] != b"MZ":
            return []
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if len(data) < pe_offset + 0x18 + 2:
            return []
        is64 = int.from_bytes(data[pe_offset + 0x18 : pe_offset + 0x1A], "little") == 0x20B
        table = pe_offset + (16 if is64 else 0) + 0x98
        if len(data) < table + 8:
            return []
        cert_addr = int.from_bytes(data[table : table + 4], "little")
        cert_len = int.from_bytes(data[table + 4 : table + 8], "little")
        if cert_len < 8 or len(data) < cert_addr + 8:
            return []
        length = int.from_bytes(data[cert_addr : cert_addr + 4], "little")
        if len(data) < cert_addr + length or length <= 8:
            return []
        found = Authenticode.parse(data[cert_addr + 8 : cert_addr + length], int(time.time()))
        for sig in found:
            name = Digests.base(sig.digest_alg)
            if name is None or not sig.digest:
                if sig.flags == Signature.VALID:
                    sig.flags = Signature.UNKNOWN_ALGORITHM
                continue
            digest = Authenticode.file_digest(data, name, pe_offset, is64, cert_addr)
            if digest is None:
                if sig.flags == Signature.VALID:
                    sig.flags = Signature.INTERNAL_ERROR
                break
            sig.file_digest = digest
            if digest != sig.digest[: len(digest)] or len(sig.digest) < len(digest):
                sig.flags = Signature.WRONG_FILE_DIGEST
        return found

    # -- the module's values -------------------------------------------------

    CERT_FIELDS: ClassVar[tuple[str, ...]] = ("thumbprint", "issuer", "subject", "version", "algorithm", "algorithm_oid", "serial", "not_before", "not_after")  # fmt: skip

    @staticmethod
    def certificate_proto() -> Struct:
        return Struct(
            {
                k: UNDEF_INT if k in ("version", "not_before", "not_after") else UNDEF_STR
                for k in Authenticode.CERT_FIELDS
            }
        )

    @staticmethod
    def proto() -> Struct:
        """One `pe.signatures` element, undefined."""
        cert = Authenticode.certificate_proto
        fields: dict[str, Any] = cert().fields | {
            "verified": UNDEF_INT, "digest_alg": UNDEF_STR, "digest": UNDEF_STR, "file_digest": UNDEF_STR,
            "number_of_certificates": UNDEF_INT, "certificates": Array(cert()),
            "signer_info": Struct({"program_name": UNDEF_STR, "digest": UNDEF_STR, "digest_alg": UNDEF_STR,
                                   "length_of_chain": UNDEF_INT, "chain": Array(cert())}),
            "number_of_countersignatures": UNDEF_INT,
            "countersignatures": Array(Struct({"verified": UNDEF_INT, "sign_time": UNDEF_INT, "digest_alg": UNDEF_STR,
                                               "digest": UNDEF_STR, "length_of_chain": UNDEF_INT, "chain": Array(cert())})),
        }  # fmt: skip
        fields["valid_on"] = Authenticode._valid_on(UNDEF_INT, UNDEF_INT)
        return Struct(fields)

    @staticmethod
    def _valid_on(not_before: Any, not_after: Any) -> Any:
        def valid_on(when: int) -> Any:
            if Values.undefined(not_before) or Values.undefined(not_after):
                return UNDEF_INT
            return int(not_before <= when <= not_after)

        return Values.fn((("int",), valid_on, "int"))

    @staticmethod
    def _certs(certs: list[Cert]) -> Array:
        out = Array(Authenticode.certificate_proto())
        for i, cert in enumerate(certs):
            out.items[i] = Struct(Authenticode.certificate_proto().fields | cert.fields())
        return out

    @staticmethod
    def module_values(data: bytes) -> tuple[list[Struct], bool]:
        """Each reported signature's Struct, and whether any verifies (`pe.is_signed`)."""
        out: list[Struct] = []
        any_valid = False
        for sig in Authenticode.signatures(data):
            if sig.flags in Signature.HIDDEN:
                continue
            verified = sig.flags == Signature.VALID
            any_valid |= verified
            s = Authenticode.proto().fields
            s["verified"] = int(verified)
            s["digest_alg"] = sig.digest_alg.encode() if sig.digest_alg is not None else UNDEF_STR
            if sig.digest:
                s["digest"] = sig.digest.hex().encode()
            if sig.file_digest:
                s["file_digest"] = sig.file_digest.hex().encode()
            s["number_of_certificates"] = len(sig.certs)
            s["certificates"] = Authenticode._certs(sig.certs)
            if sig.signer:
                info = s["signer_info"].fields
                if sig.chain:
                    s.update(sig.chain[0].fields())
                if sig.program_name is not None:
                    info["program_name"] = sig.program_name
                if sig.signer_digest_alg is not None:
                    info["digest_alg"] = sig.signer_digest_alg.encode()
                if sig.signer_digest:
                    info["digest"] = sig.signer_digest.hex().encode()
                info["length_of_chain"] = len(sig.chain)
                info["chain"] = Authenticode._certs(sig.chain)
            counters = sig.countersigs or []
            s["number_of_countersignatures"] = len(counters)
            array = s["countersignatures"]
            for j, counter in enumerate(counters):
                array.items[j] = Struct({
                    "verified": int(counter.verified), "sign_time": counter.sign_time,
                    "digest_alg": counter.digest_alg.encode() if counter.digest_alg is not None else UNDEF_STR,
                    "digest": counter.digest.hex().encode() if counter.digest else UNDEF_STR,
                    "length_of_chain": len(counter.chain or []), "chain": Authenticode._certs(counter.chain or []),
                })  # fmt: skip
            s["valid_on"] = Authenticode._valid_on(s["not_before"], s["not_after"])
            out.append(Struct(s))
        return out, any_valid


__all__ = ["Authenticode"]
