"""The zip reader for cordon-rule: the `zip` module's values as a condition sees them.

YARA has no `zip` module; YARA-X has one, and its names are the schema here (`zip.proto` at v1.21.0):
`is_zip`, and per central-directory entry its `file_path`, `compression`, `uncompressed_size` and
`compressed_size`. Which bytes are a zip, and which entries it lists, follow the reference's reader so a
rule answers the same:

- the end-of-central-directory record is the last one in the final 64 KiB + 22 bytes whose comment fits
  in that window; a prefixed archive (a self-extractor, a CRX) and trailing bytes are both accepted;
- ZIP64 sizes and offsets are taken from the ZIP64 records when the classic fields are saturated;
- the central directory is found at its stated offset, or at the offset implied by where the directory
  ends, whichever holds a central header (a prefixed archive's offsets are relative to the zip);
- multi-disk archives, an inconsistent directory and an empty archive whose record is not at offset 0
  are not zips;
- entries are listed in directory order and the listing stops at the first entry that does not read
  (a bad signature, strong encryption, a record running past the directory, an unreadable ZIP64 field).

One deliberate difference, named here and in the report: the reference stops listing at 100,000
entries, a guard against its own cost. This reader lists every entry, keeping only each entry's
offset (8 bytes) and building its values when a rule reads it, so a million-entry archive costs 8 MB
and one pass, and no entry is hidden behind a count an attacker can reach.
"""

from __future__ import annotations

from array import array
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor, LazySeq
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class NotZip(Exception):
    """The archive does not open."""


class Directory:
    """Where a zip's central directory is, from its end records."""

    EOCD, ZIP64_EOCD, ZIP64_LOCATOR, CENTRAL = 0x06054B50, 0x06064B50, 0x07064B50, 0x02014B50
    EOCD_LEN, LOCATOR_LEN, CENTRAL_LEN = 22, 20, 46
    WINDOW: ClassVar[int] = 22 + 0xFFFF
    ZIP64_SEARCH: ClassVar[int] = 4096

    __slots__ = ("count", "cur", "end", "start")

    def __init__(self, cur: Cursor) -> None:
        self.cur = cur
        size = cur.n
        eocd = self._eocd(size)
        disk, cd_disk = self._u(eocd + 4, 2), self._u(eocd + 6, 2)
        if disk or cd_disk:
            raise NotZip
        count, cd_size, cd_offset = (
            self._u(eocd + 10, 2),
            self._u(eocd + 12, 4),
            self._u(eocd + 16, 4),
        )
        payload_end = eocd
        if count == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
            count, cd_size, cd_offset, payload_end = self._zip64(eocd, size)
        used = cd_offset + cd_size
        if used > payload_end:
            raise NotZip
        inferred = payload_end - used + cd_offset
        if self._signature(cd_offset, self.CENTRAL):
            start = cd_offset
        elif self._signature(inferred, self.CENTRAL) or inferred <= size:
            start = inferred
        else:
            raise NotZip
        if start + cd_size > eocd or eocd + self.EOCD_LEN > size:
            raise NotZip
        if count == 0 and cd_size == 0 and cd_offset == 0 and eocd != 0:
            raise NotZip
        self.start, self.count, self.end = start, count, payload_end

    def _u(self, at: int, width: int) -> int:
        value = self.cur.uint(at, width, "little")
        if value is ABSENT:
            raise NotZip
        return int(value)

    def _signature(self, at: int, signature: int) -> bool:
        return bool(self.cur.uint(at, 4, "little") == signature)

    def _eocd(self, size: int) -> int:
        if size < self.EOCD_LEN:
            raise NotZip
        window = min(size, self.WINDOW)
        base = size - window
        data = self.cur.data
        at = data.rfind(b"PK\x05\x06", base, size - self.EOCD_LEN + 4)
        while at >= base:
            comment = self._u(at + 20, 2)
            if at - base + self.EOCD_LEN + comment <= window:
                return at
            at = data.rfind(b"PK\x05\x06", base, at + 3)
        raise NotZip

    def _zip64(self, eocd: int, size: int) -> tuple[int, int, int, int]:
        locator = eocd - self.LOCATOR_LEN
        if locator < 0 or not self._signature(locator, self.ZIP64_LOCATOR):
            raise NotZip
        if self._u(locator + 4, 4) != 0 or self._u(locator + 16, 4) != 1:
            raise NotZip
        record = self._u(locator + 8, 8)
        if not self._signature(record, self.ZIP64_EOCD):
            start = max(locator - self.ZIP64_SEARCH, 0)
            found = self.cur.data.rfind(b"PK\x06\x06", start, locator)
            if found < 0:
                raise NotZip
            record = found
        if record + 56 > size or not self._signature(record, self.ZIP64_EOCD):
            raise NotZip
        if record + self._u(record + 4, 8) + 12 > size:
            raise NotZip
        if self._u(record + 16, 4) or self._u(record + 20, 4):
            raise NotZip
        return self._u(record + 32, 8), self._u(record + 40, 8), self._u(record + 48, 8), record


class Entries:
    """The central directory's entries, walked once for their offsets; values read on demand."""

    __slots__ = ("cur", "offsets")

    def __init__(self, directory: Directory) -> None:
        self.cur = directory.cur
        self.offsets = array("Q")
        at, left = directory.start, directory.count
        while left:
            nxt = self._next(at, directory.end)
            if nxt is None:
                break  # the listing stops at the first entry that does not read
            self.offsets.append(at)
            at, left = nxt, left - 1

    def _next(self, at: int, end: int) -> int | None:
        u = self.cur.uint
        if at + Directory.CENTRAL_LEN > self.cur.n or u(at, 4, "little") != Directory.CENTRAL:
            return None
        flags = u(at + 8, 2, "little")
        if flags & (1 << 6) or flags & (1 << 13):
            return None  # strong encryption, or a masked local header
        name, extra, comment = (u(at + o, 2, "little") for o in (28, 30, 32))
        nxt = int(at + Directory.CENTRAL_LEN + name + extra + comment)
        if nxt > end:
            return None
        sizes = Entries._sizes(self.cur, at)
        return None if sizes is None else nxt

    @staticmethod
    def _sizes(cur: Cursor, at: int) -> tuple[int, int] | None:
        """(compressed, uncompressed), through the ZIP64 extra field when either is saturated."""
        u = cur.uint
        compressed, uncompressed, local = (
            u(at + 20, 4, "little"),
            u(at + 24, 4, "little"),
            u(at + 42, 4, "little"),
        )
        full = 0xFFFFFFFF
        if full not in (compressed, uncompressed, local):
            return int(compressed), int(uncompressed)
        name, extra = u(at + 28, 2, "little"), u(at + 30, 2, "little")
        if extra > 256:
            return None
        field_at, end = at + Directory.CENTRAL_LEN + name, at + Directory.CENTRAL_LEN + name + extra
        while end - field_at >= 4:
            kind, length = u(field_at, 2, "little"), u(field_at + 2, 2, "little")
            body = field_at + 4
            if body + length > end:
                return None
            if kind == 0x0001:
                values: list[int | None] = []
                pos = body
                for needed in (uncompressed == full, compressed == full, local == full):
                    if needed:
                        if pos + 8 > body + length:
                            return None
                        values.append(int(u(pos, 8, "little")))
                        pos += 8
                    else:
                        values.append(None)
                big_u, big_c, _ = values
                return (big_c if big_c is not None else int(compressed),
                        big_u if big_u is not None else int(uncompressed))  # fmt: skip
            field_at = body + length
        return None

    def entry(self, index: int) -> dict[str, Any]:
        at = self.offsets[index]
        u, data = self.cur.uint, self.cur.data
        name = int(u(at + 28, 2, "little"))
        method = int(u(at + 10, 2, "little"))
        compressed, uncompressed = Entries._sizes(self.cur, at) or (0, 0)
        path = data[at + Directory.CENTRAL_LEN : at + Directory.CENTRAL_LEN + name]
        return {
            "file_path": path.decode("utf-8", "replace").encode("utf-8"),
            "compression": method if method in Zip.METHODS else Zip.UNKNOWN,
            "uncompressed_size": uncompressed,
            "compressed_size": compressed,
        }


class Zip:
    """The `zip` module reader."""

    COMPRESSION: ClassVar[dict[str, int]] = {
        "STORED": 0, "SHRUNK": 1, "REDUCED_1": 2, "REDUCED_2": 3, "REDUCED_3": 4, "REDUCED_4": 5,
        "IMPLODED": 6, "DEFLATED": 8, "DEFLATE64": 9, "PKWARE_IMPLODING": 10, "BZIP2": 12, "LZMA": 14,
        "ZSTD": 93, "XZ": 95, "UNKNOWN": 255,
    }  # fmt: skip
    METHODS: ClassVar[frozenset[int]] = frozenset(COMPRESSION.values())
    UNKNOWN: ClassVar[int] = 255

    _entry = Record(
        {"file_path": TEXT, "compression": INT, "uncompressed_size": INT, "compressed_size": INT}
    )
    SCHEMA: ClassVar[Record] = Record(
        {**dict.fromkeys(COMPRESSION, INT), "is_zip": BOOL, "entries": Seq(_entry)}
    )

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = dict(Zip.COMPRESSION)  # the constants are there for every file
        try:
            entries = Entries(Directory(Cursor(file)))
        except NotZip:
            out.update(is_zip=False, entries={})
            return out
        out["is_zip"] = True
        out["entries"] = LazySeq(range(len(entries.offsets)), entries.entry)
        return out


__all__ = ["Zip"]
