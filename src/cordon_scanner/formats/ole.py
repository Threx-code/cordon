"""OLE compound files (`.doc`, `.xls`, `.ppt`, `vbaProject.bin`) and the VBA source inside them.

A compound file is a small FAT filesystem in one file (MS-CFB). VBA source is kept in it
compressed (MS-OVBA 2.4.1), one stream per module, at an offset the `dir` stream records. Macro
text has to be decompressed before anything can be said about it: `AutoOpen` and `Shell` in the
compressed bytes are split by copy tokens often enough that matching the raw stream misses them.

Every chain walk is bounded by the file's own sector count and refuses a loop, and decompressed
output is capped, so a crafted file costs at most a linear pass over itself.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from cordon_scanner.formats import FormatError

MAGIC: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_STREAM_BYTES: Final = 32 << 20
MAX_ENTRIES: Final = 4096
MAX_SOURCE_BYTES: Final = 4 << 20
"""Decompressed VBA per module. Real modules are kilobytes; a larger claim is a bomb."""

_END: Final = 0xFFFFFFFE
_FREE: Final = 0xFFFFFFFF
_NOSTREAM: Final = 0xFFFFFFFF


@dataclass(frozen=True)
class Entry:
    path: str
    kind: int
    start: int
    size: int


class CompoundFile:
    """Read-only, bounded access to the streams of an MS-CFB file."""

    def __init__(self, data: bytes) -> None:
        if data[:8] != MAGIC or len(data) < 512:
            raise FormatError("not an OLE compound file")
        self.data = data
        sector_shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise FormatError("unsupported compound file sector size")
        self.sector = 1 << int(sector_shift)
        self.mini = 1 << int(mini_shift)
        (
            fat_count,
            dir_start,
            self.cutoff,
            minifat_start,
            minifat_count,
            difat_start,
            difat_count,
        ) = struct.unpack_from("<II4xIIIII", data, 0x2C)
        self.sectors: int = max((len(data) - 512) // self.sector, 0)
        fat_sectors = [s for s in struct.unpack_from("<109I", data, 0x4C) if s < self.sectors]
        seen: set[int] = set()
        current = difat_start
        per = self.sector // 4 - 1
        while current < self.sectors and current not in seen and len(seen) <= difat_count:
            seen.add(current)
            values = struct.unpack_from(f"<{per + 1}I", data, self._offset(current))
            fat_sectors.extend(v for v in values[:per] if v < self.sectors)
            current = values[per]
        self.fat: list[int] = []
        for sector in fat_sectors[: fat_count or len(fat_sectors)]:
            self.fat.extend(struct.unpack_from(f"<{self.sector // 4}I", data, self._offset(sector)))
        root_start, root_size, raw_entries = self._entries(self._chain(dir_start))
        self.ministream = self._chain(root_start)[:root_size] if root_size else b""
        self.minifat: list[int] = []
        if minifat_count and minifat_start < self.sectors:
            table = self._chain(minifat_start)
            self.minifat = list(struct.unpack_from(f"<{len(table) // 4}I", table))
        self.entries = raw_entries

    def _offset(self, sector: int) -> int:
        if sector >= self.sectors:
            raise FormatError("a sector reference points past the end of the file")
        return 512 + sector * self.sector

    def _chain(self, start: int) -> bytes:
        parts: list[bytes] = []
        seen: set[int] = set()
        current = start
        while current not in (_END, _FREE):
            if current in seen:
                raise FormatError("a sector chain loops")
            seen.add(current)
            if len(seen) * self.sector > MAX_STREAM_BYTES:
                raise FormatError("a stream is larger than the reader's limit")
            offset = self._offset(current)
            parts.append(self.data[offset : offset + self.sector])
            current = self.fat[current] if current < len(self.fat) else _END
        return b"".join(parts)

    def _mini_bytes(self, start: int) -> bytes:
        parts: list[bytes] = []
        seen: set[int] = set()
        current = start
        while current not in (_END, _FREE):
            if current in seen or current >= len(self.minifat):
                if current in seen:
                    raise FormatError("a mini-sector chain loops")
                break
            seen.add(current)
            parts.append(self.ministream[current * self.mini : (current + 1) * self.mini])
            current = self.minifat[current]
        return b"".join(parts)

    def _entries(self, directory: bytes) -> tuple[int, int, list[Entry]]:
        count = min(len(directory) // 128, MAX_ENTRIES)
        raw: list[tuple[str, int, int, int, int, int, int]] = []
        for index in range(count):
            record = directory[index * 128 : (index + 1) * 128]
            length = struct.unpack_from("<H", record, 64)[0]
            name = record[: max(min(length, 64) - 2, 0)].decode("utf-16-le", errors="replace")
            kind = record[66]
            left, right, child = struct.unpack_from("<III", record, 68)
            start, size = struct.unpack_from("<II", record, 116)
            raw.append((name, kind, left, right, child, start, size))
        if not raw or raw[0][1] != 5:
            raise FormatError("the compound file has no root entry")
        entries: list[Entry] = []
        visited: set[int] = set()
        pending: list[tuple[int, str]] = [(raw[0][4], "")]
        while pending:
            index, prefix = pending.pop()
            if index == _NOSTREAM or index >= len(raw) or index in visited:
                continue
            visited.add(index)
            name, kind, left, right, child, start, size = raw[index]
            path = f"{prefix}{name}"
            entries.append(Entry(path, kind, start, size))
            pending.extend([(left, prefix), (right, prefix)])
            if kind == 1:
                pending.append((child, path + "/"))
        return raw[0][5], raw[0][6], entries

    def open(self, entry: Entry) -> bytes:
        if entry.kind != 2:
            raise FormatError(f"{entry.path} is not a stream")
        if entry.size > MAX_STREAM_BYTES:
            raise FormatError(f"{entry.path} is larger than the reader's limit")
        if entry.size < self.cutoff:
            return self._mini_bytes(entry.start)[: entry.size]
        return self._chain(entry.start)[: entry.size]

    def find(self, name: str) -> list[Entry]:
        """Entries whose last path component is `name`, case-insensitively."""
        lowered = name.lower()
        return [e for e in self.entries if e.path.rsplit("/", 1)[-1].lower() == lowered]


def decompress(data: bytes, start: int = 0) -> bytes:
    """MS-OVBA 2.4.1 decompression of the container at `start`."""
    if start >= len(data) or data[start] != 0x01:
        raise FormatError("not a compressed VBA container")
    out = bytearray()
    position = start + 1
    while position + 2 <= len(data):
        header = struct.unpack_from("<H", data, position)[0]
        chunk_end = min(position + 2 + (header & 0x0FFF) + 1, len(data))
        position += 2
        chunk_start = len(out)
        if not header & 0x8000:
            out += data[position : position + 4096]
            position += 4096
        else:
            while position < chunk_end:
                flags = data[position]
                position += 1
                for bit in range(8):
                    if position >= chunk_end:
                        break
                    if not flags & (1 << bit):
                        out.append(data[position])
                        position += 1
                        continue
                    if position + 2 > len(data):
                        raise FormatError("a copy token runs past the end of the container")
                    token = struct.unpack_from("<H", data, position)[0]
                    position += 2
                    difference = len(out) - chunk_start
                    bits = max((difference - 1).bit_length(), 4)
                    length_mask = 0xFFFF >> bits
                    offset = (token >> (16 - bits)) + 1
                    length = (token & length_mask) + 3
                    source = len(out) - offset
                    if source < chunk_start:
                        raise FormatError("a copy token points before its chunk")
                    for index in range(length):
                        out.append(out[source + index])
            position = chunk_end
        if len(out) > MAX_SOURCE_BYTES:
            raise FormatError("VBA source decompresses past the reader's limit")
    return bytes(out)


@dataclass(frozen=True)
class VbaModule:
    name: str
    source: str


def vba_modules(compound: CompoundFile) -> list[VbaModule]:
    """Every VBA module's source text in the file, or an empty list when it has no macros."""
    dirs = [e for e in compound.find("dir") if e.path.lower().endswith("vba/dir")]
    modules: list[VbaModule] = []
    for directory in dirs:
        storage = directory.path[: -len("dir")]
        streams = {
            e.path.rsplit("/", 1)[-1].lower(): e
            for e in compound.entries
            if e.path.startswith(storage)
        }
        try:
            records = _dir_records(decompress(compound.open(directory)))
        except FormatError:
            records = []
        for stream_name, offset in records:
            entry = streams.get(stream_name.lower())
            if entry is None:
                continue
            data = compound.open(entry)
            try:
                text = decompress(data, offset)
            except FormatError:
                text = _search_source(data)
            modules.append(VbaModule(stream_name, text.decode("latin-1")))
        if not records:
            # The `dir` stream is unreadable; modules still start with `Attribute VB_Name`.
            for name, entry in streams.items():
                if name in ("dir", "_vba_project") or name.startswith("__srp_"):
                    continue
                text = _search_source(compound.open(entry))
                if text:
                    modules.append(VbaModule(entry.path.rsplit("/", 1)[-1], text.decode("latin-1")))
    return modules


def _dir_records(data: bytes) -> list[tuple[str, int]]:
    """(stream name, source offset) for each module the decompressed `dir` stream declares."""
    found: list[tuple[str, int]] = []
    position = 0
    name = ""
    while position + 6 <= len(data):
        record, size = struct.unpack_from("<HI", data, position)
        position += 6
        if record == 0x0009:
            size = 6  # PROJECTVERSION declares 4 and holds 6.
        value = data[position : position + size]
        position += size
        if record == 0x001A:
            name = value.decode("latin-1")
        elif record == 0x0031 and len(value) == 4 and name:
            found.append((name, struct.unpack("<I", value)[0]))
            name = ""
        elif record == 0x0010:
            break
    return found


def _search_source(data: bytes) -> bytes:
    """Decompress from the first container that starts `Attribute`, as every module does."""
    index = data.find(b"\x00Attribut")
    if index < 3:
        return b""
    try:
        return decompress(data, index - 3)
    except FormatError:
        return b""


__all__ = ["MAGIC", "CompoundFile", "Entry", "VbaModule", "decompress", "vba_modules"]
