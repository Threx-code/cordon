"""``pe.signatures``: a file's Authenticode signatures, read on Cordon's own primitives.

Each signature holds its signer, the certificates in the PKCS #7 SignedData, the timestamp
countersignatures (PKCS #9 and Microsoft's), each certificate as OpenSSL formats it, the chain built
from the signer with no trust anchors, and whether the signature signs the file's bytes. The ASN.1
layer is here; RSA is modular exponentiation, ECDSA and DSA come from ``intel.provenance`` -- there is
no OpenSSL and no third-party code, only the behaviour matched to it.

It is as lenient as OpenSSL and no more: BER indefinite and long-form lengths and constructed strings
are read; a non-minimal integer, a misplaced field, a name value of a type no string allows are refused
exactly where OpenSSL's templates refuse them, with the same effect on what a rule sees. ``verified``
means the signature signs the file's bytes; it is not trust, and no root is consulted. The reference
engine's recorded output is what the tests hold this to.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_layout import ABSENT, Cursor
from cordon_scanner.detect.binary.rule_oids import ObjectIds
from cordon_scanner.detect.binary.rule_values import Call, Record, Scalar, Seq, Sig
from cordon_scanner.intel.provenance._dsa import Dsa
from cordon_scanner.intel.provenance._ecdsa import Ecdsa


class BadDer(ValueError):
    """The bytes are not what OpenSSL's decoder would accept."""


@dataclass(slots=True)
class Tlv:
    """One decoded ASN.1 element: its class/number, whether it is constructed, the whole element's
    bytes (``span``), its content bytes (``body``), and -- once asked for -- its members."""

    klass: int
    constructed: bool
    tag: int
    span: bytes
    body: bytes
    members: list[Tlv] | None = None
    indefinite: bool = False

    UNIVERSAL: ClassVar[int] = 0
    CONTEXT: ClassVar[int] = 2
    DEPTH_LIMIT: ClassVar[int] = 64

    # -- shape tests ---------------------------------------------------------

    def is_tag(self, number: int) -> bool:
        return self.klass == Tlv.UNIVERSAL and self.tag == number

    def is_context(self, number: int) -> bool:
        return self.klass == Tlv.CONTEXT and self.tag == number

    def insist(self, number: int, *, constructed: bool | None = None) -> Tlv:
        if not self.is_tag(number) or (constructed is not None and self.constructed != constructed):
            raise BadDer(f"expected universal {number}")
        return self

        # -- members -------------------------------------------------------------

    def unpack(self) -> list[Tlv]:
        """The members of a constructed element (decoding its body the first time asked)."""
        if not self.constructed:
            raise BadDer("not constructed")
        if self.members is None:
            found, at = [], 0
            while at < len(self.body):
                child, at = Tlv._decode(self.body, at, 1)
                found.append(child)
            self.members = found
        return self.members

    def row(self, size: tuple[int, int] | int | None = None) -> list[Tlv]:
        """A SEQUENCE's members, with an optional count or (low, high) range."""
        if not self.is_tag(16) or not self.constructed:
            raise BadDer("not a SEQUENCE")
        out = self.unpack()
        low, high = (size, size) if isinstance(size, int) else size or (0, 1 << 30)
        if not low <= len(out) <= high:
            raise BadDer("a SEQUENCE of the wrong length")
        return out

    def bag(self) -> list[Tlv]:
        """A SET's members."""
        if not self.constructed or not self.is_tag(17):
            raise BadDer("not a SET")
        return self.unpack()

    def tagged_bag(self, number: int) -> list[Tlv]:
        """An implicitly-tagged SET's members (a context-tagged constructed element)."""
        if not self.is_context(number) or not self.constructed:
            raise BadDer("not an implicit SET")
        return self.unpack()

        # -- leaves --------------------------------------------------------------

    def joined(self) -> bytes:
        """A string's bytes; a constructed string is its pieces joined (``asn1_collect``)."""
        if not self.constructed:
            return self.body
        return b"".join(piece.joined() for piece in self.unpack())

    def whole_number(self) -> int:
        if not self.is_tag(2) or self.constructed:
            raise BadDer("not an INTEGER")
        return Tlv.number_from(self.body)

    @staticmethod
    def number_from(raw: bytes) -> int:
        """OpenSSL 1.1's ``c2i_ibuf``: content required, and no superfluous padding octet."""
        if not raw:
            raise BadDer("an empty integer")
        if len(raw) > 1 and (
            (raw[0] == 0 and raw[1] < 0x80) or (raw[0] == 0xFF and raw[1] >= 0x80 and any(raw[1:]))
        ):
            raise BadDer("an integer with padding")
        return int(Cursor(raw).uint(0, len(raw), "big", signed=True))

    def object_id(self) -> str:
        if not self.is_tag(6) or self.constructed:
            raise BadDer("not an OBJECT IDENTIFIER")
        raw = self.body
        if not raw or raw[-1] & 0x80:
            raise BadDer("a malformed object identifier")
        arcs: list[int] = []
        acc = 0
        for i, byte in enumerate(raw):
            if byte == 0x80 and (i == 0 or not raw[i - 1] & 0x80):
                raise BadDer("an arc with a leading zero")
            acc = (acc << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(acc)
                acc = 0
        lead = arcs[0]
        head = [0, lead] if lead < 40 else [1, lead - 40] if lead < 80 else [2, lead - 80]
        return ".".join(str(x) for x in head + arcs[1:])

    def bytes_of(self) -> bytes:
        if not self.is_tag(4):
            raise BadDer("not an OCTET STRING")
        return self.joined()

    @staticmethod
    def decode(data: bytes) -> Tlv:
        """The first ASN.1 element in ``data``; anything after it is ignored, as ``d2i`` ignores it."""
        return Tlv._decode(data, 0, 0)[0]

    @staticmethod
    def decode_whole(data: bytes) -> Tlv:
        """Decode as OpenSSL's template ``d2i`` does -- the declared structure is read in full, and a
        malformation anywhere the template declares structure (a length past a parent, a fragment left over
        inside a constructed element, a child that does not decode) fails the whole decode, which is why the
        reference reports nothing at all for a certificate or timestamp whose body is scattered even a little.
        d2i never looks inside the types the template leaves opaque -- a BIT STRING or OCTET STRING (a public
        key, a signature, an extension's value, a timestamp's eContent) -- so those are not descended into;
        their contents are decoded later, in their own ``d2i``. Our plain ``decode`` is lazy, so the strict
        walk is explicit here and used wherever ``d2i`` is (each certificate, each countersignature, nested
        signatures, the TSTInfo)."""
        node = Tlv.decode(data)
        Tlv._decode_fully(node)
        return node

    @staticmethod
    def _decode_fully(node: Tlv) -> None:
        # BIT STRING and OCTET STRING are opaque to a template decoder: their bytes are decoded only later,
        # by whatever reads that field, so a scatter inside one does not fail the enclosing structure
        if node.constructed and not (node.klass == Tlv.UNIVERSAL and node.tag in (3, 4)):
            children = node.unpack()  # raises on a truncated or over-long child
            if sum(len(child.span) for child in children) != len(node.body):
                raise BadDer("a constructed element its children do not fill exactly")
            for child in children:
                Tlv._decode_fully(child)

    @staticmethod
    def _decode(data: bytes, at: int, depth: int) -> tuple[Tlv, int]:
        if depth > Tlv.DEPTH_LIMIT:
            raise BadDer("nested too deeply")
        cur = Cursor(data)
        start = at
        tag_byte = Tlv._byte(cur, at)
        at += 1
        klass, constructed, tag = tag_byte >> 6, bool(tag_byte & 0x20), tag_byte & 0x1F
        if tag == 0x1F:
            tag = 0
            while True:
                if tag >> 28:
                    raise BadDer("a tag out of range")
                more = Tlv._byte(cur, at)
                at += 1
                tag = (tag << 7) | (more & 0x7F)
                if not more & 0x80:
                    break
        length_byte = Tlv._byte(cur, at)
        at += 1
        if length_byte == 0x80:
            return Tlv._indefinite(cur, data, klass, constructed, tag, start, at, depth)
        if length_byte & 0x80:
            count = length_byte & 0x7F
            length = cur.uint(at, count, "big") if count else 0
            if count > 8 or length is ABSENT:
                raise BadDer("a length out of range")
            at += count
        else:
            length = length_byte
        end = at + length
        if end > len(data):
            raise BadDer("a value past the end")
        return Tlv(klass, constructed, tag, data[start:end], data[at:end]), end

    @staticmethod
    def _indefinite(
        cur: Cursor,
        data: bytes,
        klass: int,
        constructed: bool,
        tag: int,
        start: int,
        at: int,
        depth: int,
    ) -> tuple[Tlv, int]:
        if not constructed:
            raise BadDer("an indefinite length on a primitive")
        members: list[Tlv] = []
        body_start = at
        while True:
            if at + 2 > len(data):
                raise BadDer("no end-of-contents")
            if data[at] == 0 and data[at + 1] == 0:
                body = data[body_start:at]
                at += 2
                break
            child, at = Tlv._decode(data, at, depth + 1)
            members.append(child)
        node = Tlv(klass, constructed, tag, data[start:at], body, members, indefinite=True)
        return node, at

    @staticmethod
    def _byte(cur: Cursor, at: int) -> int:
        value = cur.uint(at, 1)
        if value is ABSENT:
            raise BadDer("truncated")
        return int(value)

    @staticmethod
    def _alg_oid(node: Tlv) -> str:
        """The OID of an AlgorithmIdentifier (its parameters, if any, ignored)."""
        return node.row((1, 2))[0].object_id()


class Hash:
    """OpenSSL 1.1's message digests, named by the identifier that selects one."""

    #: an RSA signature identifier is registered as a name for its digest (``EVP_add_digest``)
    BASE :ClassVar [dict [str ,str ]]={
    "md5WithRSAEncryption":"md5","sha1WithRSAEncryption":"sha1","mdc2WithRSA":"mdc2",
    "ripemd160WithRSA":"ripemd160","md4WithRSAEncryption":"md4",
    "sha224WithRSAEncryption":"sha224","sha256WithRSAEncryption":"sha256",
    "sha384WithRSAEncryption":"sha384","sha512WithRSAEncryption":"sha512",
    "sha512-224WithRSAEncryption":"sha512-224","sha512-256WithRSAEncryption":"sha512-256",
    "RSA-SHA3-224":"sha3-224","RSA-SHA3-256":"sha3-256","RSA-SHA3-384":"sha3-384",
    "RSA-SHA3-512":"sha3-512","sm3WithRSAEncryption":"sm3",
    }  # fmt: skip
    TO_HASHLIB :ClassVar [dict [str ,str ]]={
    "sha512-224":"sha512_224","sha512-256":"sha512_256","sha3-224":"sha3_224",
    "sha3-256":"sha3_256","sha3-384":"sha3_384","sha3-512":"sha3_512",
    "blake2b512":"blake2b","blake2s256":"blake2s","shake128":"shake_128","shake256":"shake_256",
    }  # fmt: skip
    #: digests RSA PKCS #1 v1.5 signs with in OpenSSL 1.1 (``check_padding_md``)
    RSA :ClassVar [frozenset [str ]]=frozenset (
    {"sha1","sha224","sha256","sha384","sha512","sha512-224","sha512-256","md5","md4",
    "mdc2","ripemd160","sha3-224","sha3-256","sha3-384","sha3-512"}
    )  # fmt: skip
    _BY_NAME: ClassVar[dict[str, str]] = {}

    @staticmethod
    def identifier(name: str) -> str | None:
        """The OID of a digest, by its long name (the digests OpenSSL keys by name)."""
        if not Hash._BY_NAME:
            for oid, (_short, long) in ObjectIds.NAMES.items():
                if long in ObjectIds.DIGEST_SIZES and long not in Hash.BASE:
                    Hash._BY_NAME[long] = oid
        return Hash._BY_NAME.get(name)

    @staticmethod
    def oid_long_name(oid: str) -> str:
        """``OBJ_nid2ln(OBJ_obj2nid(oid))``: "undefined" for an identifier OpenSSL does not know."""
        names = ObjectIds.NAMES.get(oid)
        return (names[1] or "undefined") if names else "undefined"

    @staticmethod
    def base(name: str | None) -> str | None:
        """The digest ``EVP_get_digestbyname`` gives, or None."""
        if name is None or name not in ObjectIds.DIGEST_SIZES:
            return None
        return Hash.BASE.get(name, name)

    @staticmethod
    def compute(name: str, data: bytes) -> bytes | None:
        """The digest, or None where this hashlib lacks one OpenSSL has."""
        size = ObjectIds.DIGEST_SIZES[name]
        try:
            digest = hashlib.new(Hash.TO_HASHLIB.get(name, name), data)
        except ValueError:
            return None
        return digest.digest(size) if name.startswith("shake") else digest.digest()  # type: ignore[call-arg]


class Clock:
    """OpenSSL 1.1's ``ASN1_TIME_to_tm`` then ``timegm``, turning a time into seconds."""

    #: ``timegm`` of the zeroed ``struct tm`` the parser falls back to: day 0 of January 1900
    FALLBACK: ClassVar[int] = -2209075200
    LOW: ClassVar[tuple[int, ...]] = (0, 0, 1, 1, 0, 0, 0, 0, 0)
    HIGH: ClassVar[tuple[int, ...]] = (99, 99, 12, 31, 23, 59, 59, 12, 59)
    MONTH_DAYS: ClassVar[tuple[int, ...]] = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

    @staticmethod
    def seconds(node: Tlv | None) -> int | None:
        """Seconds since the epoch, or None when OpenSSL could not read the time."""
        if node is None or node.constructed or not (node.is_tag(23) or node.is_tag(24)):
            return None
        utc = node.is_tag(23)
        text = node.body
        fields, tz_at, shortest = (6, 5, 11) if utc else (7, 6, 13)
        length = len(text)
        if length < shortest:
            return None
        year = month = day = hour = minute = second = 0
        pos = field_no = 0
        while field_no < fields:
            if field_no == tz_at and pos < length and text[pos] in b"Z+-":
                break
            if pos + 1 >= length or not (
                0x30 <= text[pos] <= 0x39 and 0x30 <= text[pos + 1] <= 0x39
            ):
                return None
            value = (text[pos] - 0x30) * 10 + text[pos + 1] - 0x30
            pos += 2
            if pos == length:
                return None
            slot = field_no + 1 if utc else field_no
            if not Clock.LOW[slot] <= value <= Clock.HIGH[slot]:
                return None
            if slot == 0:
                year = value * 100
            elif slot == 1:
                year = (2000 + value if value < 50 else 1900 + value) if utc else year + value
            elif slot == 2:
                month = value
            elif slot == 3:
                leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
                if value > Clock.MONTH_DAYS[month - 1] + (1 if month == 2 and leap else 0):
                    return None
                day = value
            elif slot == 4:
                hour = value
            elif slot == 5:
                minute = value
            else:
                second = value
            field_no += 1
        if not utc and pos < length and text[pos] == 0x2E:
            pos += 1
            if pos == length:
                return None
            first = pos
            while pos < length and 0x30 <= text[pos] <= 0x39:
                pos += 1
            if pos in (first, length):
                return None
        shift = 0
        if pos < length and text[pos] == 0x5A:
            pos += 1
        elif pos < length and text[pos] in b"+-":
            sign = 1 if text[pos] == 0x2D else -1
            pos += 1
            if pos + 4 != length:
                return None
            for k in range(2):
                if not (0x30 <= text[pos] <= 0x39 and 0x30 <= text[pos + 1] <= 0x39):
                    return None
                value = (text[pos] - 0x30) * 10 + text[pos + 1] - 0x30
                slot = fields + k + (1 if utc else 0)
                if not Clock.LOW[slot] <= value <= Clock.HIGH[slot]:
                    return None
                shift += value * 3600 if k == 0 else value * 60
                pos += 2
            shift *= sign
        else:
            return None
        if pos != length:
            return None
        return Clock.timegm(year, month, day, hour, minute, second) + shift

    @staticmethod
    def timegm(year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
        """``timegm`` over the proleptic Gregorian calendar (days-from-civil)."""
        y = year - (month <= 2)
        era = y // 400
        year_of_era = y - era * 400
        day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
        days = (
            era * 146097
            + year_of_era * 365
            + year_of_era // 4
            - year_of_era // 100
            + day_of_year
            - 719468
        )
        return days * 86400 + hour * 3600 + minute * 60 + second

    @staticmethod
    def at_or_fallback(node: Tlv | None) -> int:
        value = Clock.seconds(node)
        return Clock.FALLBACK if value is None else value


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
        )

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


class Encode:
    """The few DER encodings re-made here, as OpenSSL's ``i2d`` makes them, to check a signature."""

    @staticmethod
    def der_length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        width = (n.bit_length() + 7) // 8
        return bytes([0x80 | width]) + n.to_bytes(width, "big")

    @staticmethod
    def wrap(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + Encode.der_length(len(body)) + body

    @staticmethod
    def signed_attributes(attrs: list[Tlv]) -> bytes:
        """Signed attributes as ``PKCS7_ATTR_VERIFY`` re-encodes them to check a signature: a SET in
        the order they came, each attribute in DER with its values sorted."""
        return Encode.wrap(0x31, b"".join(Encode._der_attribute(a) for a in attrs))

    @staticmethod
    def _der_attribute(attr: Tlv) -> bytes:
        kind, values = attr.unpack()
        ordered = sorted((Encode._der_any(v) for v in values.unpack()), key=lambda e: (e, len(e)))
        return Encode.wrap(
            0x30, Encode.wrap(0x06, kind.body) + Encode.wrap(0x31, b"".join(ordered))
        )

    @staticmethod
    def _der_any(value: Tlv) -> bytes:
        """An ASN1_TYPE as ``i2d`` writes it: SEQUENCE, SET and tagged values as they came; a universal
        primitive (a constructed string joined first) in its shortest length."""
        if value.klass != Tlv.UNIVERSAL or value.tag in (16, 17) or value.tag >= 31:
            return value.span
        return Encode.wrap(value.tag, value.joined())

    @staticmethod
    def pkcs1_wrap(digest_name: str, digest: bytes) -> bytes | None:
        oid = Hash.identifier(digest_name)
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
        algorithm = Encode.wrap(0x30, Encode.wrap(0x06, bytes(body)) + b"\x05\x00")
        return Encode.wrap(0x30, algorithm + Encode.wrap(0x04, digest))


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


@dataclass(slots=True)
class Signer:
    """One PKCS #7 (or CMS) SignerInfo."""

    node: Tlv
    issuer: X500 | None
    serial: int | None
    key_id: bytes | None
    digest_oid: str
    signed_attrs: list[Tlv] | None
    signature: bytes
    unsigned_attrs: list[Tlv] | None

    @staticmethod
    def parse(node: Tlv, *, cms: bool) -> Signer:
        parts = node.row((5, 7))
        parts[0].whole_number()
        sid = parts[1]
        issuer: X500 | None = None
        serial: int | None = None
        key_id: bytes | None = None
        if sid.is_tag(16):
            name, number = sid.row(2)
            issuer, serial = X500.parse(name), number.whole_number()
        elif cms and sid.is_context(0) and not sid.constructed:
            key_id = sid.body
        else:
            raise BadDer("a signer identified by neither issuer and serial nor key")
        digest_oid = Tlv._alg_oid(parts[2])
        at = 3
        signed_attrs: list[Tlv] | None = None
        if parts[at].is_context(0):
            signed_attrs = parts[at].tagged_bag(0)
            at += 1
        if at + 2 > len(parts):
            raise BadDer("a signer info missing a field")
        Tlv._alg_oid(parts[at])
        signature = parts[at + 1].bytes_of()
        unsigned_attrs: list[Tlv] | None = None
        if at + 2 < len(parts):
            unsigned_attrs = parts[at + 2].tagged_bag(1)
            if at + 3 < len(parts):
                raise BadDer("a signer info with fields out of place")
        for attr in (signed_attrs or []) + (unsigned_attrs or []):
            pair = attr.row(2)
            pair[0].object_id()
            pair[1].bag()
        return Signer(
            node, issuer, serial, key_id, digest_oid, signed_attrs, signature, unsigned_attrs
        )

    @staticmethod
    def values_of(attrs: list[Tlv] | None, oid: str) -> list[Tlv] | None:
        """The values of the first attribute of this type (``X509at_get_attr_by_NID``)."""
        for attr in attrs or []:
            kind, values = attr.unpack()
            if kind.object_id() == oid:
                return values.unpack()
        return None

    def first(self, oid: str, *, signed: bool) -> Tlv | None:
        values = Signer.values_of(self.signed_attrs if signed else self.unsigned_attrs, oid)
        return values[0] if values else None

    def locate(self, certs: list[Certificate]) -> Certificate | None:
        """The certificate this signer names: by subject key id when it gives one, else by the issuer
        name and serial number."""

        def names(cert: Certificate) -> bool:
            if self.key_id is not None:
                return cert.subject_key_id is not None and cert.subject_key_id == self.key_id
            return (
                self.issuer is not None
                and cert.serial == self.serial
                and cert.issuer.key == self.issuer.key
            )

        return next((cert for cert in certs if names(cert)), None)


@dataclass(slots=True)
class Pkcs7:
    """PKCS #7 (or, for a timestamp, CMS) SignedData."""

    version: int
    digest_oids: list[str]
    content_type: str
    content: Tlv | None
    certs: list[Certificate]
    signers: list[Signer]

    SIGNED: ClassVar[str] = "1.2.840.113549.1.7.2"

    @staticmethod
    def parse(data: bytes, *, cms: bool = False, strict: bool = False) -> tuple[str, Pkcs7 | None]:
        """The ContentInfo's type and, when it is SignedData, the SignedData."""
        outer = (Tlv.decode_whole(data) if strict else Tlv.decode(data)).row((1, 2))
        kind = outer[0].object_id()
        if kind != Pkcs7.SIGNED:
            if cms:
                raise BadDer("not SignedData")
            if len(outer) == 2 and not (outer[1].is_context(0) and outer[1].constructed):
                raise BadDer("a content that is not [0]")
            return kind, None
        if len(outer) == 1:
            if cms:
                raise BadDer("SignedData without content")
            return kind, None
        if not (outer[1].is_context(0) and outer[1].constructed):
            raise BadDer("a content that is not [0]")
        (body,) = outer[1].unpack()
        parts = body.row((4, 6))
        version = parts[0].whole_number()
        digest_oids = [Tlv._alg_oid(a) for a in parts[1].bag()]
        inner = parts[2].row((1, 2))
        content_type = inner[0].object_id()
        content: Tlv | None = None
        if len(inner) == 2:
            if not (inner[1].is_context(0) and inner[1].constructed):
                raise BadDer("an inner content that is not [0]")
            (content,) = inner[1].unpack()
            if cms and not content.is_tag(4):
                raise BadDer("encapsulated content that is not an OCTET STRING")
        at = 3
        certs: list[Certificate] = []
        if parts[at].is_context(0):
            for choice in parts[at].unpack():
                if choice.is_tag(16):
                    certs.append(Certificate.parse(choice))
                elif not cms:
                    raise BadDer("a certificate choice PKCS #7 does not have")
            at += 1
        if at < len(parts) and parts[at].is_context(1):
            at += 1
        if at != len(parts) - 1:
            raise BadDer("SignedData with fields out of place")
        signers = [Signer.parse(s, cms=cms) for s in parts[at].bag()]
        return kind, Pkcs7(version, digest_oids, content_type, content, certs, signers)

    def digest_bases(self) -> list[str] | None:
        """The digests the data is hashed with; None when OpenSSL does not know one."""
        names = []
        for oid in self.digest_oids:
            base = Hash.base(Hash.oid_long_name(oid))
            if base is None:
                return None
            names.append(base)
        return names

    def verifies_content(self, si: Signer, cert: Certificate, content: bytes) -> bool:
        """``PKCS7_signatureVerify``: the signed attributes' digest of the content, then the
        signature over those attributes (or, with none, over the content)."""
        names = self.digest_bases()
        name = Hash.base(Hash.oid_long_name(si.digest_oid))
        if names is None or name is None or name not in names:
            return False
        digest = Hash.compute(name, content)
        if digest is None:
            return False
        if si.signed_attrs:
            claimed = si.first("1.2.840.113549.1.9.4", signed=True)
            if claimed is None or claimed.joined() != digest:
                return False
            over_attrs = Hash.compute(name, Encode.signed_attributes(si.signed_attrs))
            if over_attrs is None:
                return False
            digest = over_attrs
        return PublicKey.verifies(cert.spki, name, digest, si.signature)


@dataclass(slots=True)
class Countersign:
    """A timestamp countersignature: PKCS #9 (a SignerInfo) or Microsoft's (a nested SignedData)."""

    verified: bool = False
    sign_time: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    chain: list[Certificate] | None = None
    certs: list[Certificate] | None = None

    MSG_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"
    SIGN_TIME_OID: ClassVar[str] = "1.2.840.113549.1.9.5"

    @staticmethod
    def from_pkcs9(
        value: Tlv, certs: list[Certificate], parent_signature: bytes, when: int
    ) -> Countersign:
        out = Countersign()
        try:
            si = Signer.parse(value, cms=False)
        except (BadDer, ValueError, IndexError):
            return out
        out.digest_alg = Hash.oid_long_name(si.digest_oid)
        stamped = si.first(Countersign.SIGN_TIME_OID, signed=True)
        if stamped is None:
            return out
        out.sign_time = Clock.at_or_fallback(stamped)
        cert = si.locate(certs)
        if cert is None:
            return out
        out.chain = ChainWalk.build(cert, certs, when)
        claimed = si.first(Countersign.MSG_DIGEST, signed=True)
        claimed_digest = claimed.joined() if claimed is not None else b""
        if not claimed_digest:
            return out
        name = Hash.base(out.digest_alg)
        if name is None:
            return out
        out.digest = claimed_digest
        over_attrs = Hash.compute(name, Encode.signed_attributes(si.signed_attrs or []))
        recovered = PublicKey.rsa_recover(cert.spki, si.signature, exact=False)
        if over_attrs is None or recovered is None:
            return out
        size = ObjectIds.DIGEST_SIZES[name]
        if len(recovered) == size:
            good = recovered == over_attrs
        else:
            try:
                good = Tlv.decode(recovered).row(2)[1].bytes_of()[:size] == over_attrs
            except (BadDer, ValueError, IndexError):
                good = False
        if not good:
            return out
        expected = Hash.compute(name, parent_signature)
        out.verified = (
            expected is not None and len(claimed_digest) == size and claimed_digest == expected
        )
        return out

    @staticmethod
    def from_microsoft(value: Tlv, parent_signature: bytes, when: int) -> Countersign:
        out = Countersign()
        cms = False
        try:
            signed = Pkcs7.parse(value.span, strict=True)[1]
            if signed is None:
                return out
        except (BadDer, ValueError, IndexError):
            try:
                _, signed = Pkcs7.parse(value.span, cms=True, strict=True)
                cms = True
            except (BadDer, ValueError, IndexError):
                return out
        if signed is None:
            return out
        stamp = Countersign._timestamp_info(signed)
        if stamp is None:
            return out
        version, gen_time, imprint_oid, imprint = stamp
        out.sign_time = Clock.at_or_fallback(gen_time)
        cert = Countersign._find_signer(signed, cms=cms)
        if cert is None:
            return out
        out.certs = list(signed.certs)
        out.chain = ChainWalk.build(cert, signed.certs, when)
        out.digest_alg = Hash.oid_long_name(imprint_oid)
        out.digest = imprint or None
        if not imprint:
            return out
        name = Hash.base(out.digest_alg)
        if name is None:
            return out
        expected = Hash.compute(name, parent_signature)
        if expected is None or imprint != expected or version != 1:
            return out
        content = (
            signed.content.joined()
            if signed.content is not None and signed.content.is_tag(4)
            else b""
        )
        si = signed.signers[0]
        if cms:
            out.verified = Countersign._cms_verify(signed, si, content)
        else:
            out.verified = signed.verifies_content(si, cert, content)
        return out

    @staticmethod
    def _timestamp_info(signed: Pkcs7) -> tuple[int, Tlv | None, str, bytes] | None:
        if signed.content_type != "1.2.840.113549.1.9.16.1.4" or signed.content is None:
            return None
        if not signed.content.is_tag(4):
            return None
        try:
            parts = Tlv.decode(signed.content.joined()).row((5, 10))
            version = parts[0].whole_number()
            parts[1].object_id()
            imprint_alg, imprint = parts[2].row(2)
            oid = Tlv._alg_oid(imprint_alg)
            digest = imprint.bytes_of()
            parts[3].whole_number()
            gen_time = parts[4]
            if not gen_time.is_tag(24):
                return None
        except (BadDer, ValueError, IndexError):
            return None
        return version, gen_time, oid, digest

    @staticmethod
    def _find_signer(signed: Pkcs7, *, cms: bool) -> Certificate | None:
        # each signer resolves to its own certificate by the same rule as the main signature; a CMS
        # timestamp takes the first signer that resolves, a PKCS #7 one needs every signer to resolve
        if not signed.signers:
            return None
        resolved = [si.locate(signed.certs) for si in signed.signers]
        if cms:
            return next((cert for cert in resolved if cert is not None), None)
        return None if any(cert is None for cert in resolved) else resolved[0]

    @staticmethod
    def _cms_verify(signed: Pkcs7, si: Signer, content: bytes) -> bool:
        """``CMS_SignerInfo_verify_content``: the content's digest against the signed one."""
        names = signed.digest_bases()
        name = Hash.base(Hash.oid_long_name(si.digest_oid))
        if names is None or name is None or name not in names or si.signed_attrs is None:
            return False
        claimed = [
            v
            for a in si.signed_attrs
            for k, v in [a.unpack()]
            if k.object_id() == Countersign.MSG_DIGEST
        ]
        if (
            len(claimed) != 1
            or len(claimed[0].unpack()) != 1
            or not claimed[0].unpack()[0].is_tag(4)
        ):
            return False
        digest = Hash.compute(name, content)
        return digest is not None and claimed[0].unpack()[0].joined() == digest


@dataclass(slots=True)
class Signed:
    """One Authenticode signature (the parser's ``Authenticode`` struct)."""

    flags: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    authenticode_digest: bytes | None = None
    certs: list[Certificate] | None = None
    has_signer: bool = False
    chain: list[Certificate] | None = None
    signer_digest_alg: str | None = None
    signer_digest: bytes | None = None
    program_name: bytes | None = None
    countersigs: list[Countersign] | None = None

    CLEAN: ClassVar[int] = 0
    UNREADABLE: ClassVar[int] = 1
    SIGNER_ABSENT: ClassVar[int] = 2
    DIGEST_ABSENT: ClassVar[int] = 3
    DIGEST_ERROR: ClassVar[int] = 4
    SIGNER_INFO_ABSENT: ClassVar[int] = 5
    NOT_SIGNED_DATA: ClassVar[int] = 6
    CONTENT_BAD: ClassVar[int] = 7
    UNVERIFIED: ClassVar[int] = 8
    FILE_DIGEST_WRONG: ClassVar[int] = 9
    ALGORITHM_UNKNOWN: ClassVar[int] = 10
    #: outcomes the reference reports no signature for
    SUPPRESSED: ClassVar[frozenset[int]] = frozenset({1, 2, 4, 5, 6})
    MAX_NESTED: ClassVar[int] = 16
    MAX_DEPTH: ClassVar[int] = 32


INT, TEXT = Scalar.INT, Scalar.TEXT

CERTIFICATE :Record =Record ({
"thumbprint":TEXT ,"issuer":TEXT ,"subject":TEXT ,"version":INT ,"algorithm":TEXT ,
"algorithm_oid":TEXT ,"serial":TEXT ,"not_before":INT ,"not_after":INT ,
})  # fmt: skip

SIGNATURE :Record =Record ({
"thumbprint":TEXT ,"issuer":TEXT ,"subject":TEXT ,"version":INT ,"algorithm":TEXT ,
"algorithm_oid":TEXT ,"serial":TEXT ,"not_before":INT ,"not_after":INT ,
"verified":INT ,"digest_alg":TEXT ,"digest":TEXT ,"file_digest":TEXT ,
"number_of_certificates":INT ,"certificates":Seq (CERTIFICATE ),
"signer_info":Record ({
"program_name":TEXT ,"digest":TEXT ,"digest_alg":TEXT ,
"length_of_chain":INT ,"chain":Seq (CERTIFICATE ),
}),
"number_of_countersignatures":INT ,
"countersignatures":Seq (Record ({
"verified":INT ,"sign_time":INT ,"digest_alg":TEXT ,"digest":TEXT ,
"length_of_chain":INT ,"chain":Seq (CERTIFICATE ),
})),
"valid_on":Call (Sig (("int",),INT )),
})  # fmt: skip


class Signatures:
    """``pe.signatures``: the Authenticode signatures of a file (``parse_authenticode``)."""

    SPC_INDIRECT: ClassVar[str] = "1.3.6.1.4.1.311.2.1.4"
    SPC_OPUS: ClassVar[str] = "1.3.6.1.4.1.311.2.1.12"
    SPC_NESTED: ClassVar[str] = "1.3.6.1.4.1.311.2.4.1"
    MS_TIMESTAMP: ClassVar[str] = "1.3.6.1.4.1.311.3.3.1"
    PKCS9_COUNTERSIG: ClassVar[str] = "1.2.840.113549.1.9.6"
    MSG_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"

    @staticmethod
    def parse(blob: bytes, now: int, depth: int = 0) -> list[Signed]:
        """``authenticode_new``: this signature, then the ones nested in it."""
        if not blob:
            return []
        sig = Signed()
        out = [sig]
        try:
            _, signed = Pkcs7.parse(blob)
        except (BadDer, ValueError, IndexError):
            sig.flags = Signed.UNREADABLE
            return out
        if signed is None:
            sig.flags = Signed.NOT_SIGNED_DATA
            return out
        sig.certs = list(signed.certs)
        content = Signatures._spc_indirect(signed)
        if content is None:
            sig.flags = Signed.CONTENT_BAD
            return out
        sig.digest_alg, sig.digest = Hash.oid_long_name(content[0]), content[1]
        sig.has_signer = True
        if not signed.signers:
            sig.flags = Signed.SIGNER_INFO_ABSENT
            return out
        si = signed.signers[0]
        sig.countersigs = []
        nested = Signer.values_of(si.unsigned_attrs, Signatures.SPC_NESTED) or []
        if depth < Signed.MAX_DEPTH:
            for value in nested[: Signed.MAX_NESTED]:
                out.extend(Signatures.parse(value.span, now, depth + 1))
        for value in (Signer.values_of(si.unsigned_attrs, Signatures.PKCS9_COUNTERSIG) or [])[
            : Signed.MAX_NESTED
        ]:
            sig.countersigs.append(Countersign.from_pkcs9(value, signed.certs, si.signature, now))
        for value in (Signer.values_of(si.unsigned_attrs, Signatures.MS_TIMESTAMP) or [])[
            : Signed.MAX_NESTED
        ]:
            counter = Countersign.from_microsoft(value, si.signature, now)
            sig.countersigs.append(counter)
            sig.certs.extend(counter.certs or [])
        resolved = [s.locate(signed.certs) for s in signed.signers]
        cert = None if any(c is None for c in resolved) else resolved[0]
        if cert is None:
            sig.flags = Signed.SIGNER_ABSENT
            return out
        sig.chain = ChainWalk.build(cert, signed.certs, now)
        claimed = si.first(Signatures.MSG_DIGEST, signed=True)
        if claimed is None:
            sig.flags = Signed.DIGEST_ABSENT
            return out
        sig.signer_digest_alg = Hash.oid_long_name(si.digest_oid)
        sig.signer_digest = claimed.joined() or None
        opus = si.first(Signatures.SPC_OPUS, signed=True)
        if opus is not None:
            sig.program_name = Signatures._opus_program(opus)
        inner = signed.content.span if signed.content is not None else b""
        if signed.version == 1 and signed.content is not None:
            inner = b"" if signed.content.indefinite else signed.content.body
        if not signed.verifies_content(si, cert, inner):
            sig.flags = Signed.UNVERIFIED
        return out

    @staticmethod
    def _spc_indirect(signed: Pkcs7) -> tuple[str, bytes] | None:
        """SpcIndirectDataContent's digest algorithm and digest."""
        if signed.content_type != Signatures.SPC_INDIRECT or signed.content is None:
            return None
        try:
            data, pkcs1_wrap = Tlv.decode(signed.content.span).row(2)
            data.row((1, 2))[0].object_id()
            algorithm, digest = pkcs1_wrap.row(2)
            return Tlv._alg_oid(algorithm), digest.bytes_of()
        except (BadDer, ValueError, IndexError):
            return None

    @staticmethod
    def _opus_program(opus: Tlv) -> bytes | None:
        if not opus.is_tag(16):
            return None
        try:
            for part in opus.row((0, 2)):
                if part.is_context(0) and part.constructed:
                    (choice,) = part.unpack()
                    raw = choice.joined()
                    if choice.is_context(0):
                        if len(raw) % 2:
                            return None
                        name = raw.decode("utf-16-be", "surrogatepass").encode(
                            "utf-8", "surrogatepass"
                        )
                    elif choice.is_context(1):
                        name = raw.decode("latin-1").encode("utf-8")
                    else:
                        return None
                    return name if len(name) < len(opus.span) else None
        except (BadDer, ValueError, IndexError, UnicodeDecodeError):
            return None
        return None

    @staticmethod
    def authenticode_digest(
        data: bytes, name: str, pe_offset: int, is64: bool, cert_addr: int
    ) -> bytes | None:
        """The Authenticode digest: everything before the certificate table, less the checksum and
        the table's own directory entry."""
        checksum_at = pe_offset + 0x58
        directory_at = checksum_at + 4 + 0x3C + (16 if is64 else 0)
        if cert_addr < directory_at + 8:
            return None
            # the digest covers the file with two windows removed: the 4-byte checksum, and the 8-byte
            # security directory entry; everything from there to the certificate table is included
        kept = bytearray(data[:checksum_at])
        kept += data[checksum_at + 4 : directory_at]
        kept += data[directory_at + 8 : cert_addr]
        return Hash.compute(name, bytes(kept))

    @staticmethod
    def read(data: bytes, now: int) -> list[Signed]:
        """``parse_authenticode``: every signature in the first certificate, with file digests."""
        cur = Cursor(data)
        if len(data) < 0x40 or data[:2] != b"MZ":
            return []
        pe_offset = cur.uint(0x3C, 4, "little")
        if pe_offset is ABSENT or len(data) < pe_offset + 0x18 + 2:
            return []
        is64 = cur.uint(pe_offset + 0x18, 2, "little") == 0x20B
        table = pe_offset + (16 if is64 else 0) + 0x98
        if len(data) < table + 8:
            return []
        cert_addr = cur.uint(table, 4, "little")
        cert_len = cur.uint(table + 4, 4, "little")
        # the security directory (a file offset and a size) must lie within the file, as the reference requires
        # before it reads the table at all; without this a corrupted directory yields a phantom signature
        if (
            cert_addr == 0
            or cert_addr > len(data)
            or cert_len > len(data)
            or cert_addr + cert_len > len(data)
        ):
            return []
        if cert_len < 8 or len(data) < cert_addr + 8:
            return []
        length = cur.uint(cert_addr, 4, "little")
        if len(data) < cert_addr + length or length <= 8:
            return []
        found = Signatures.parse(data[cert_addr + 8 : cert_addr + length], now)
        for sig in found:
            name = Hash.base(sig.digest_alg)
            if name is None or not sig.digest:
                if sig.flags == Signed.CLEAN:
                    sig.flags = Signed.ALGORITHM_UNKNOWN
                continue
            digest = Signatures.authenticode_digest(data, name, pe_offset, is64, cert_addr)
            if digest is None:
                if sig.flags == Signed.CLEAN:
                    sig.flags = Signed.DIGEST_ERROR
                break
            sig.authenticode_digest = digest
            if digest != sig.digest[: len(digest)] or len(sig.digest) < len(digest):
                sig.flags = Signed.FILE_DIGEST_WRONG
        return found

    @staticmethod
    def _present(fields: dict[str, Any]) -> dict[str, Any]:
        """A cert's fields with the absent ones (None) dropped, as the reference omits an undefined value."""
        return {k: v for k, v in fields.items() if v is not None}

    @staticmethod
    def _cert_seq(certs: list[Certificate]) -> dict[int, Any]:
        return {i: Signatures._present(cert.fields()) for i, cert in enumerate(certs)}

    @staticmethod
    def _validity_call(not_before: int | None, not_after: int | None) -> Any:
        def valid_on(when: int) -> int | None:
            if not_before is None or not_after is None:
                return None
            return int(not_before <= when <= not_after)

        return valid_on

    @staticmethod
    def signature_values(data: bytes) -> tuple[dict[int, Any], int]:
        """``pe.signatures`` as schema-first data (a Seq of SIGNATURE), and ``pe.is_signed``: every
        reported signature, each with the signer certificate's fields flattened in, as the reference reports it."""
        out: dict[int, Any] = {}
        any_valid = 0
        for sig in Signatures.read(data, int(time.time())):
            if sig.flags in Signed.SUPPRESSED:
                continue
            verified = sig.flags == Signed.CLEAN
            any_valid |= int(verified)
            rec: dict[str, Any] = {"verified": int(verified)}
            if sig.digest_alg is not None:
                rec["digest_alg"] = sig.digest_alg.encode()
            if sig.digest:
                rec["digest"] = sig.digest.hex().encode()
            if sig.authenticode_digest:
                rec["file_digest"] = sig.authenticode_digest.hex().encode()
            certs = sig.certs or []
            rec["number_of_certificates"] = len(certs)
            rec["certificates"] = Signatures._cert_seq(certs)
            signer: dict[str, Any] = {}
            if sig.has_signer:
                if sig.chain:
                    rec.update(Signatures._present(sig.chain[0].fields()))
                if sig.program_name is not None:
                    signer["program_name"] = sig.program_name
                if sig.signer_digest_alg is not None:
                    signer["digest_alg"] = sig.signer_digest_alg.encode()
                if sig.signer_digest:
                    signer["digest"] = sig.signer_digest.hex().encode()
                signer["length_of_chain"] = len(sig.chain or [])
                signer["chain"] = Signatures._cert_seq(sig.chain or [])
            rec["signer_info"] = signer
            counters = sig.countersigs or []
            rec["number_of_countersignatures"] = len(counters)
            block: dict[int, Any] = {}
            for j, counter in enumerate(counters):
                one: dict[str, Any] = {
                    "verified": int(counter.verified),
                    "sign_time": counter.sign_time,
                    "length_of_chain": len(counter.chain or []),
                    "chain": Signatures._cert_seq(counter.chain or []),
                }
                if counter.digest_alg is not None:
                    one["digest_alg"] = counter.digest_alg.encode()
                if counter.digest:
                    one["digest"] = counter.digest.hex().encode()
                block[j] = one
            rec["countersignatures"] = block
            rec["valid_on"] = (
                Signatures._validity_call(rec.get("not_before"), rec.get("not_after")),
            )
            out[len(out)] = rec
        return out, any_valid
