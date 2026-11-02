"""The RAR 5 archive, read in our own code (item 76).

RAR was in item 53's list of formats no reader opens. Of the npm pool's RAR members, almost all are
compressed (method 3, "normal"), so only a decoder reads them. This is one: the RAR 5 container (blocks
behind a CRC32 each, files with their compression info) and its one compression algorithm, a Huffman
coded LZ77 with four repeat distances and the delta, x86 E8, E8E9 and ARM filters:

```
  "Rar!\\x1a\\x07\\x01\\x00" ─► main header ─► file header [+ data] ... ─► end header
  data: blocks [flags, checksum, size]; a block with tables: 20 bit lengths ─► 430 code lengths
        ─► literal/length (306), distance (64), low distance (16), repeat length (44)
```

Read fully, never guessed: every header's CRC is checked, every file's CRC32 where it is stated, and a
file is held only once its declared size is reached exactly. Refused, as the archive's error (a gap that
blocks): encryption (archive or file), a multi-volume archive, a RAR 7 large-dictionary file, a
distance past what was written, a stream that ends early. RAR 2.9 and older (signature `Rar!\\x1a\\x07\\x00`)
stay unopened: `UnopenedFormats` reports them, measured in note 76. Sizes are declared before any byte
is decoded, so the archive budget binds first; output is held in memory, at most the budget.
"""

from __future__ import annotations

import struct
import time
import zlib
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.sources.archive_names import MemberNames
from cordon_scanner.sources.base import RejectedMember, Rejection

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.foundation.limits import Limits
    from cordon_scanner.sources.archive import ExtractionResult

MAGIC5 = b"Rar!\x1a\x07\x01\x00"


class _Fail(Exception):
    """Inside the decoder: the archive's error, raised as ArchiveError with its path by the caller."""


class _Header:
    """One RAR 5 header's fields, read with the format's variable-length integers."""

    def __init__(self, data: bytes, at: int) -> None:
        self.data = data
        if at + 4 > len(data):
            raise _Fail("a header past the archive's end")
        crc = struct.unpack_from("<I", data, at)[0]
        size, self.at = _Header.vint(data, at + 4)
        self.end = self.at + size
        if size < 1 or self.end > len(data) or zlib.crc32(data[at + 4 : self.end]) != crc:
            raise _Fail("a header whose CRC does not hold")
        self.type = self.next()
        self.flags = self.next()
        self.extra = self.next() if self.flags & 0x01 else 0
        self.data_size = self.next() if self.flags & 0x02 else 0

    @staticmethod
    def vint(data: bytes, at: int) -> tuple[int, int]:
        value = shift = 0
        for _ in range(10):
            if at >= len(data):
                raise _Fail("a number past the archive's end")
            byte = data[at]
            at += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, at
        raise _Fail("a number longer than ten bytes")

    def next(self) -> int:
        value, self.at = _Header.vint(self.data, self.at)
        if self.at > self.end:
            raise _Fail("a field past its header's end")
        return value

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > self.end:
            raise _Fail("a field past its header's end")
        self.at += count
        return self.data[self.at - count : self.at]

    def extras(self) -> list[tuple[int, bytes]]:
        """The extra area's records: (type, body)."""
        out, at, stop = [], self.end - self.extra, self.end
        while at < stop:
            size, body = _Header.vint(self.data, at)
            if body + size > stop or size < 1:
                raise _Fail("an extra record past its header")
            kind, rest = _Header.vint(self.data, body)
            out.append((kind, self.data[rest : body + size]))
            at = body + size
        return out


class _Bits:
    """The compressed stream's bits, most significant first."""

    def __init__(self, data: bytes) -> None:
        self.data = data + b"\x00" * 8
        self.limit = len(data) * 8
        self.pos = 0

    def peek(self, count: int) -> int:
        at = self.pos >> 3
        word = int.from_bytes(self.data[at : at + 4], "big")
        return (word >> (32 - (self.pos & 7) - count)) & ((1 << count) - 1)

    def bits(self, count: int) -> int:
        if not count:
            return 0
        if count > 24:
            high = self.bits(count - 16)
            return (high << 16) | self.bits(16)
        value = self.peek(count)
        self.pos += count
        return value

    def align(self) -> None:
        self.pos = (self.pos + 7) & ~7


class _Huffman:
    """A canonical Huffman code: a direct table for codes up to `QUICK` bits, a walk beyond."""

    QUICK: ClassVar[int] = 10

    def __init__(self, lengths: list[int]) -> None:
        self.quick: list[tuple[int, int]] = [(-1, 0)] * (1 << _Huffman.QUICK)
        self.lengths = lengths
        counts = [0] * 16
        for length in lengths:
            counts[length] += 1
        counts[0] = 0
        code, first, start = 0, [0] * 16, [0] * 16
        index = 0
        self.ordered: list[int] = []
        for length in range(1, 16):
            code = (code + counts[length - 1]) << 1 if length > 1 else 0
            first[length], start[length] = code, index
            index += counts[length]
        self.first, self.start, self.counts = first, start, counts
        by_length: list[list[int]] = [[] for _ in range(16)]
        for symbol, length in enumerate(lengths):
            if length:
                by_length[length].append(symbol)
        for length in range(1, 16):
            self.ordered.extend(by_length[length])
            for offset, symbol in enumerate(by_length[length]):
                if length <= _Huffman.QUICK:
                    prefix = (first[length] + offset) << (_Huffman.QUICK - length)
                    for fill in range(1 << (_Huffman.QUICK - length)):
                        self.quick[prefix + fill] = (symbol, length)

    def decode(self, bits: _Bits) -> int:
        symbol, length = self.quick[bits.peek(_Huffman.QUICK)]
        if symbol >= 0:
            bits.pos += length
            return symbol
        code = bits.peek(15)
        for length in range(_Huffman.QUICK + 1, 16):
            prefix = code >> (15 - length)
            offset = prefix - self.first[length]
            if 0 <= offset < self.counts[length]:
                bits.pos += length
                return self.ordered[self.start[length] + offset]
        raise _Fail("a code no table holds")


class _Unpack:
    """RAR 5's decoder for one stream (one file, or a solid run of files), output held whole."""

    NC, DC, LDC, RC = 306, 64, 16, 44

    def __init__(self, budget: int) -> None:
        self.out = bytearray()
        self.budget = budget
        self.old = [0, 0, 0, 0]
        self.last_length = 0
        self.tables: tuple[_Huffman, _Huffman, _Huffman, _Huffman] | None = None
        self.filters: list[tuple[int, int, int, int]] = []  # start, length, type, channels
        self.done = 0  # output before this position is final (filters applied)

    def run(self, packed: bytes, size: int) -> bytes:
        """`size` more bytes of output from `packed`, the file's own data."""
        start, goal = len(self.out), len(self.out) + size
        if goal > self.budget:
            raise _Fail("output past the archive budget")
        bits = _Bits(packed)
        while len(self.out) < goal:
            if bits.pos >= bits.limit:
                raise _Fail("a stream that ends before its declared size")
            last = self._block(bits, goal)
            if last and len(self.out) < goal:
                raise _Fail("a last block before the declared size")
        self._apply(goal)
        if len(self.out) != goal:
            raise _Fail("a stream that decodes past its declared size")
        return bytes(self.out[start:goal])

    def _block(self, bits: _Bits, goal: int) -> bool:
        bits.align()
        flags = bits.bits(8)
        checksum = bits.bits(8)
        count = ((flags >> 3) & 3) + 1
        if count == 4:
            raise _Fail("a block size field of four bytes")
        size = 0
        for i in range(count):
            size |= bits.bits(8) << (8 * i)
        if (0x5A ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xFF != checksum:
            raise _Fail("a block header whose checksum does not hold")
        end = bits.pos + 8 * size - (8 - ((flags & 7) + 1)) if size else bits.pos
        if end > bits.limit + 8:
            raise _Fail("a block past the stream's end")
        if flags & 0x80:
            self.tables = self._tables(bits)
        if self.tables is None:
            raise _Fail("a block with no tables before it")
        self._symbols(bits, end, goal)
        bits.pos = end
        return bool(flags & 0x40)

    def _tables(self, bits: _Bits) -> tuple[_Huffman, _Huffman, _Huffman, _Huffman]:
        lengths20: list[int] = []
        while len(lengths20) < 20:
            length = bits.bits(4)
            if length == 15:
                zeros = bits.bits(4)
                if zeros:
                    lengths20.extend([0] * min(zeros + 2, 20 - len(lengths20)))
                    continue
            lengths20.append(length)
        bc = _Huffman(lengths20)
        total = _Unpack.NC + _Unpack.DC + _Unpack.LDC + _Unpack.RC
        table: list[int] = []
        while len(table) < total:
            number = bc.decode(bits)
            if number < 16:
                table.append(number)
            elif number < 18:
                if not table:
                    raise _Fail("a repeat with nothing before it")
                n = bits.bits(3) + 3 if number == 16 else bits.bits(7) + 11
                table.extend([table[-1]] * min(n, total - len(table)))
            else:
                n = bits.bits(3) + 3 if number == 18 else bits.bits(7) + 11
                table.extend([0] * min(n, total - len(table)))
        a, b, c = _Unpack.NC, _Unpack.NC + _Unpack.DC, _Unpack.NC + _Unpack.DC + _Unpack.LDC
        return _Huffman(table[:a]), _Huffman(table[a:b]), _Huffman(table[b:c]), _Huffman(table[c:])

    @staticmethod
    def _length(bits: _Bits, slot: int) -> int:
        if slot < 8:
            return 2 + slot
        lbits = slot // 4 - 1
        return 2 + ((4 | (slot & 3)) << lbits) + bits.bits(lbits)

    def _symbols(self, bits: _Bits, end: int, goal: int) -> None:
        if self.tables is None:
            raise _Fail("a block with no tables before it")
        ld, dd, ldd, rd = self.tables
        out = self.out
        while bits.pos < end and len(out) < goal:
            slot = ld.decode(bits)
            if slot < 256:
                out.append(slot)
                continue
            if slot >= 262:
                length = _Unpack._length(bits, slot - 262)
                dslot = dd.decode(bits)
                distance = 1
                if dslot < 4:
                    distance += dslot
                else:
                    dbits = dslot // 2 - 1
                    distance += (2 | (dslot & 1)) << dbits
                    if dbits >= 4:
                        if dbits > 4:
                            distance += bits.bits(dbits - 4) << 4
                        distance += ldd.decode(bits)
                    else:
                        distance += bits.bits(dbits)
                if distance > 0x100:
                    length += 1
                if distance > 0x2000:
                    length += 1
                if distance > 0x40000:
                    length += 1
                self.old = [distance, *self.old[:3]]
                self.last_length = length
                self._copy(length, distance, goal)
            elif slot == 256:
                self._filter(bits)
            elif slot == 257:
                if self.last_length:
                    self._copy(self.last_length, self.old[0], goal)
            else:
                index = slot - 258
                distance = self.old[index]
                self.old = [distance, *self.old[:index], *self.old[index + 1 :]]
                length = _Unpack._length(bits, rd.decode(bits))
                self.last_length = length
                self._copy(length, distance, goal)
            if len(out) > self.budget:
                raise _Fail("output past the archive budget")

    def _copy(self, length: int, distance: int, goal: int) -> None:
        out = self.out
        if distance < 1 or distance > len(out):
            raise _Fail("a distance past what was written")
        length = min(length, goal - len(out))  # a file ends at its declared size
        start = len(out) - distance
        if distance >= length:
            out += out[start : start + length]
        else:
            while length > 0:
                chunk = out[start : start + min(length, distance)]
                out += chunk
                length -= len(chunk)

    def _filter(self, bits: _Bits) -> None:
        def number() -> int:
            count, value = bits.bits(2) + 1, 0
            for i in range(count):
                value |= bits.bits(8) << (8 * i)
            return value

        start, length = number(), number()
        kind = bits.bits(3)
        channels = bits.bits(5) + 1 if kind == 0 else 0
        if kind > 3:
            raise _Fail(f"a filter of unknown type {kind}")
        if length > 0x400000:
            raise _Fail("a filter block past 4 MB")
        self.filters.append((len(self.out) + start, length, kind, channels))

    def _apply(self, goal: int) -> None:
        """Every filter whose block lies within the output, in order, on the output itself."""
        for start, length, kind, channels in self.filters:
            if start + length > len(self.out):
                raise _Fail("a filter past the decoded output")
            block = bytes(self.out[start : start + length])
            self.out[start : start + length] = _Filters.run(kind, block, start, channels)
        self.filters = []


class _Filters:
    @staticmethod
    def run(kind: int, data: bytes, offset: int, channels: int) -> bytes:
        if kind == 0:
            return _Filters.delta(data, channels)
        if kind in (1, 2):
            return _Filters.e8(data, offset, kind == 2)
        return _Filters.arm(data, offset)

    @staticmethod
    def delta(data: bytes, channels: int) -> bytes:
        out = bytearray(len(data))
        src = 0
        for channel in range(channels):
            prev = 0
            for pos in range(channel, len(data), channels):
                prev = (prev - data[src]) & 0xFF
                out[pos] = prev
                src += 1
        return bytes(out)

    @staticmethod
    def e8(data: bytes, offset: int, e9: bool) -> bytes:
        out = bytearray(data)
        size, file_size, cur = len(out), 0x1000000, 0
        while cur + 4 < size:
            byte = out[cur]
            cur += 1
            if byte == 0xE8 or (e9 and byte == 0xE9):
                where = (cur + offset) % file_size
                addr = struct.unpack_from("<I", out, cur)[0]
                if addr & 0x80000000:
                    if not (addr + where) & 0x80000000:
                        struct.pack_into("<I", out, cur, (addr + file_size) & 0xFFFFFFFF)
                elif (addr - file_size) & 0x80000000:
                    struct.pack_into("<I", out, cur, (addr - where) & 0xFFFFFFFF)
                cur += 4
        return bytes(out)

    @staticmethod
    def arm(data: bytes, offset: int) -> bytes:
        out = bytearray(data)
        for cur in range(0, len(out) - 3, 4):
            if out[cur + 3] == 0xEB:
                value = out[cur] | (out[cur + 1] << 8) | (out[cur + 2] << 16)
                value = (value - (offset + cur) // 4) & 0xFFFFFF
                out[cur : cur + 3] = value.to_bytes(3, "little")
        return bytes(out)


class RarReader:
    """Reads a RAR 5 archive held in memory into the extraction result."""

    @staticmethod
    def is_rar5(data: bytes) -> bool:
        """The signature and a main header whose CRC holds: never the magic alone."""
        if data[:8] != MAGIC5:
            return False
        try:
            return _Header(data, 8).type == 1
        except _Fail:
            return False

    @staticmethod
    def extract(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None,
        *,
        member: Callable[..., Any],
    ) -> None:
        try:
            RarReader._extract(data, path, limits, result, deadline, member)
        except _Fail as exc:
            raise ArchiveError(f"{path}: a RAR archive that does not read: {exc}") from exc

    @staticmethod
    def _extract(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None,
        member: Callable[..., Any],
    ) -> None:
        cap = getattr(result, "expansion_cap", 0) or limits.max_uncompressed_bytes
        budget = min(limits.max_uncompressed_bytes, cap)
        at, count, stream = 8, 0, _Unpack(budget)
        while at < len(data):
            if deadline is not None and time.monotonic() > deadline:
                raise ArchiveError(f"{path}: the time budget ran out while reading the archive")
            header = _Header(data, at)
            body = header.end
            at = body + header.data_size
            if at > len(data):
                raise _Fail("data past the archive's end")
            if header.type == 1:
                flags = header.next()
                if flags & 0x01:
                    raise _Fail("a multi-volume archive, not read")
            elif header.type == 4:
                raise _Fail("an encrypted archive, not read")
            elif header.type == 5:
                break
            elif header.type == 2:
                count += 1
                if count > limits.max_archive_entries:
                    result.truncated = True
                    result.rejected.append(
                        RejectedMember(
                            path,
                            Rejection.ENTRIES,
                            f"stopped after {limits.max_archive_entries} entries",
                        )
                    )
                    return
                stream = RarReader._file(header, data[body:at], stream, budget, result, member)
        result.total_compressed = max(result.total_compressed, len(data))

    @staticmethod
    def _file(
        header: _Header,
        packed: bytes,
        stream: _Unpack,
        budget: int,
        result: ExtractionResult,
        member: Callable[..., Any],
    ) -> _Unpack:
        flags = header.next()
        size = header.next()
        header.next()  # attributes
        if flags & 0x02:
            header.take(4)
        crc = struct.unpack("<I", header.take(4))[0] if flags & 0x04 else None
        info = header.next()
        header.next()  # host OS
        name = header.take(header.next()).decode("utf-8", "replace")
        if header.flags & 0x18:
            raise _Fail("a file split across volumes, not read")
        for kind, _ in header.extras():
            if kind == 1:
                raise _Fail("an encrypted file, not read")
            if kind == 5:
                result.rejected.append(
                    RejectedMember(name, Rejection.LINK, "a link member, never extracted")
                )
                return stream
        if flags & 0x01:
            return stream  # a directory
        if flags & 0x08:
            raise _Fail("a file of unknown size, not read")
        version, solid, method = info & 0x3F, bool(info & 0x40), (info >> 7) & 7
        if version != 0:
            raise _Fail(f"compression version {version} (RAR 7), not read")
        if size > budget or sum(len(m.data) for m in result.members) + size > budget:
            raise _Fail("files past the archive budget")
        if method == 0:
            body = packed[:size]
            if len(body) != size:
                raise _Fail("a stored file shorter than its size")
        else:
            if not solid:
                stream = _Unpack(budget)
            body = stream.run(packed, size)
        if crc is not None and zlib.crc32(body) != crc:
            raise _Fail(f"{name}: a CRC that does not hold")
        safe = MemberNames.safe_member_name(name)
        if safe is None:
            result.rejected.append(
                RejectedMember(
                    name, Rejection.TRAVERSAL, "member name escapes the destination directory"
                )
            )
            return stream
        result.total_uncompressed += len(body)
        result.members.append(
            member(name=safe, data=body, compressed_size=len(packed), uncompressed_size=len(body))
        )
        return stream


__all__ = ["MAGIC5", "RarReader"]
