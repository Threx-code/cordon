"""DER and what is read beside it, on Cordon's own primitives: tag-length-value elements of an ASN.1
encoding, walked without trusting a length the bytes cannot back; the re-encodings a signature check
needs; ASN.1 times read the way OpenSSL reads them; and the digest an algorithm identifier names.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor
from cordon_scanner.detect.binary.modules.oids import ObjectIds


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


__all__ = ["BadDer", "Clock", "Encode", "Hash", "Tlv"]
