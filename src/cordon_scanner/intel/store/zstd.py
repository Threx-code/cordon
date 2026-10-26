"""A zstd decoder in Python, for the one place the scanner meets zstd: the `info-*.tar.zst` member of
a `.conda` package (`intel/upstream_advisories.CondaPackage`). The standard library reads zstd from
Python 3.14 (`compression.zstd`); before it, this is what lets the core read a conda package with no
third-party dependency (CONSTRAINT C1). The `zstandard` package, where installed, is used first.

It follows RFC 8878: frames and skippable frames; raw, RLE and compressed blocks; raw, RLE,
Huffman-compressed and treeless literals, in one stream or four; sequences with predefined, RLE,
FSE-compressed and repeated tables; repeat offsets. A frame's content checksum (the low 32 bits of
XXH64) is checked when the frame has been read to its end. Dictionaries are refused: a conda
package never uses one. Output is produced block by block, so a reader can stop early, and is
bounded by the caller.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Iterator
from typing import IO, Any, ClassVar, Final

MAGIC: Final = 0xFD2FB528
MAX_BLOCK: Final = 128 << 10
MAX_WINDOW: Final = 1 << 31


class ZstdError(ValueError):
    """The data is not zstd this decoder reads, or is corrupt."""


class XXH64:
    P1: ClassVar[int] = 11400714785074694791
    P2: ClassVar[int] = 14029467366897019727
    P3: ClassVar[int] = 1609587929392839161
    P4: ClassVar[int] = 9650029242287828579
    P5: ClassVar[int] = 2870177450012600261
    M: ClassVar[int] = (1 << 64) - 1

    @staticmethod
    def _rotl(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (64 - bits))) & XXH64.M

    @staticmethod
    def _round(acc: int, lane: int) -> int:
        acc = (acc + lane * XXH64.P2) & XXH64.M
        return (XXH64._rotl(acc, 31) * XXH64.P1) & XXH64.M

    @staticmethod
    def digest(data: bytes, seed: int = 0) -> int:
        p1, p2, p3, p4, p5, m = XXH64.P1, XXH64.P2, XXH64.P3, XXH64.P4, XXH64.P5, XXH64.M
        size, position = len(data), 0
        if size >= 32:
            v = [(seed + p1 + p2) & m, (seed + p2) & m, seed & m, (seed - p1) & m]
            while position + 32 <= size:
                lanes = struct.unpack_from("<4Q", data, position)
                v = [XXH64._round(v[i], lanes[i]) for i in range(4)]
                position += 32
            acc = (
                XXH64._rotl(v[0], 1)
                + XXH64._rotl(v[1], 7)
                + XXH64._rotl(v[2], 12)
                + XXH64._rotl(v[3], 18)
            ) & m
            for lane in v:
                acc = ((acc ^ XXH64._round(0, lane)) * p1 + p4) & m
        else:
            acc = (seed + p5) & m
        acc = (acc + size) & m
        while position + 8 <= size:
            lane = int.from_bytes(data[position : position + 8], "little")
            acc = (XXH64._rotl(acc ^ XXH64._round(0, lane), 27) * p1 + p4) & m
            position += 8
        if position + 4 <= size:
            lane = int.from_bytes(data[position : position + 4], "little")
            acc = (XXH64._rotl(acc ^ (lane * p1 & m), 23) * p2 + p3) & m
            position += 4
        for byte in data[position:]:
            acc = (XXH64._rotl(acc ^ (byte * p5 & m), 11) * p1) & m
        acc ^= acc >> 33
        acc = (acc * p2) & m
        acc ^= acc >> 29
        acc = (acc * p3) & m
        return acc ^ (acc >> 32)


class XXH64Stream:
    """XXH64 over data given a piece at a time: the same digest as `XXH64.digest` of the whole,
    holding at most one 32-byte stripe -- so a frame's checksum never keeps its output."""

    def __init__(self, seed: int = 0) -> None:
        p1, p2, m = XXH64.P1, XXH64.P2, XXH64.M
        self.seed = seed
        self.v = [(seed + p1 + p2) & m, (seed + p2) & m, seed & m, (seed - p1) & m]
        self.buffer = b""
        self.total = 0
        self.striped = False

    def update(self, data: bytes) -> None:
        self.total += len(data)
        data = self.buffer + data
        whole = len(data) - len(data) % 32
        for at in range(0, whole, 32):
            lanes = struct.unpack_from("<4Q", data, at)
            self.v = [XXH64._round(self.v[i], lanes[i]) for i in range(4)]
            self.striped = True
        self.buffer = data[whole:]

    def digest(self) -> int:
        p1, p2, p3, p4, p5, m = XXH64.P1, XXH64.P2, XXH64.P3, XXH64.P4, XXH64.P5, XXH64.M
        v = self.v
        if self.striped:
            acc = (
                XXH64._rotl(v[0], 1) + XXH64._rotl(v[1], 7) + XXH64._rotl(v[2], 12) + XXH64._rotl(v[3], 18)
            ) & m
            for lane in v:
                acc = ((acc ^ XXH64._round(0, lane)) * p1 + p4) & m
        else:
            acc = (self.seed + p5) & m
        acc = (acc + self.total) & m
        data, position = self.buffer, 0
        while position + 8 <= len(data):
            lane = int.from_bytes(data[position : position + 8], "little")
            acc = (XXH64._rotl(acc ^ XXH64._round(0, lane), 27) * p1 + p4) & m
            position += 8
        if position + 4 <= len(data):
            lane = int.from_bytes(data[position : position + 4], "little")
            acc = (XXH64._rotl(acc ^ (lane * p1 & m), 23) * p2 + p3) & m
            position += 4
        for byte in data[position:]:
            acc = (XXH64._rotl(acc ^ (byte * p5 & m), 11) * p1) & m
        acc ^= acc >> 33
        acc = (acc * p2) & m
        acc ^= acc >> 29
        acc = (acc * p3) & m
        return acc ^ (acc >> 32)


class _Input:
    """Compressed input read as it is needed, from bytes or a stream: never held whole. Reads
    move an offset into a buffer refilled a megabyte at a time, so a small read copies nothing."""

    CHUNK: ClassVar[int] = 1 << 20

    def __init__(self, source: bytes | IO[bytes]) -> None:
        self.stream: IO[bytes] = (
            io.BytesIO(source) if isinstance(source, (bytes, bytearray, memoryview)) else source
        )
        self.buffer = b""
        self.at = 0

    def _fill(self, n: int) -> None:
        if len(self.buffer) - self.at >= n:
            return
        parts = [self.buffer[self.at :]]
        have = len(parts[0])
        while have < n:
            chunk = self.stream.read(max(n - have, _Input.CHUNK))
            if not chunk:
                break
            parts.append(chunk)
            have += len(chunk)
        self.buffer, self.at = b"".join(parts), 0

    def take(self, n: int, what: str) -> bytes:
        self._fill(n)
        if len(self.buffer) - self.at < n:
            raise ZstdError(f"{what} past the end of the data")
        out = self.buffer[self.at : self.at + n]
        self.at += n
        return out

    def skip(self, n: int, what: str) -> None:
        while n > 0:
            step = min(n, _Input.CHUNK)
            self.take(step, what)
            n -= step

    def at_end(self) -> bool:
        self._fill(1)
        return len(self.buffer) == self.at

    def left(self) -> int:
        self._fill(4)
        return len(self.buffer) - self.at


class Backward:
    """A bitstream read from its end: the last byte's highest set bit marks where it starts.
    Reading past the start yields zero bits and leaves `offset` negative, as RFC 8878 allows for
    the final reads of a stream."""

    def __init__(self, data: bytes) -> None:
        if not data or data[-1] == 0:
            raise ZstdError("a bitstream with no end marker")
        self.data = data
        self.offset = len(data) * 8 - 8 + data[-1].bit_length() - 1

    def read(self, bits: int) -> int:
        if bits == 0:
            return 0
        self.offset -= bits
        start = self.offset
        if start >= 0:
            first = start >> 3
            chunk = int.from_bytes(self.data[first : first + 9], "little")
            return (chunk >> (start & 7)) & ((1 << bits) - 1)
        available = bits + start
        if available <= 0:
            return 0
        chunk = int.from_bytes(self.data[:9], "little") & ((1 << available) - 1)
        return chunk << -start


class Fse:
    """An FSE decoding table: per state, its symbol, how many bits the next state takes, and the
    base those bits are added to."""

    def __init__(self, counts: list[int], accuracy: int) -> None:
        size = 1 << accuracy
        symbols = [0] * size
        high = size
        state: list[int] = [0] * len(counts)
        for symbol, count in enumerate(counts):
            if count == -1:
                high -= 1
                symbols[high] = symbol
                state[symbol] = 1
        step, mask, position = (size >> 1) + (size >> 3) + 3, size - 1, 0
        for symbol, count in enumerate(counts):
            if count <= 0:
                continue
            state[symbol] = count
            for _ in range(count):
                symbols[position] = symbol
                position = (position + step) & mask
                while position >= high:
                    position = (position + step) & mask
        if position != 0:
            raise ZstdError("an FSE table that does not spread")
        self.accuracy = accuracy
        self.symbols = symbols
        self.bits = [0] * size
        self.base = [0] * size
        for i in range(size):
            following = state[symbols[i]]
            state[symbols[i]] += 1
            bits = accuracy - (following.bit_length() - 1)
            self.bits[i] = bits
            self.base[i] = (following << bits) - size

    @staticmethod
    def rle(symbol: int) -> Fse:
        table = Fse.__new__(Fse)
        table.accuracy, table.symbols, table.bits, table.base = 0, [symbol], [0], [0]
        return table

    @staticmethod
    def header(data: bytes, position: int, max_accuracy: int, max_symbols: int) -> tuple[Fse, int]:
        """The table a compressed header describes, and where the header ends."""
        value = int.from_bytes(data[position : position + 128], "little")
        offset = 4
        accuracy = (value & 15) + 5
        if accuracy > max_accuracy:
            raise ZstdError("an FSE accuracy log beyond the limit")
        remaining = 1 << accuracy
        counts: list[int] = []
        while remaining > 0 and len(counts) < max_symbols:
            bits = (remaining + 1).bit_length()
            read = (value >> offset) & ((1 << bits) - 1)
            offset += bits
            lower = (1 << (bits - 1)) - 1
            threshold = (1 << bits) - 1 - (remaining + 1)
            if (read & lower) < threshold:
                offset -= 1
                read &= lower
            elif read > lower:
                read -= threshold
            count = read - 1
            remaining -= -count if count < 0 else count
            counts.append(count)
            if count == 0:
                while True:
                    repeat = (value >> offset) & 3
                    offset += 2
                    counts.extend([0] * repeat)
                    if repeat != 3:
                        break
        if remaining != 0 or len(counts) > max_symbols:
            raise ZstdError("an FSE header whose counts do not add up")
        end = position + (offset + 7) // 8
        if end > len(data):
            raise ZstdError("an FSE header past the end of its block")
        return Fse(counts, accuracy), end


class Huffman:
    """A Huffman decoding table, from the weights a literals section gives."""

    def __init__(self, weights: list[int]) -> None:
        total = sum(1 << (w - 1) for w in weights if w > 0)
        if total == 0:
            raise ZstdError("Huffman weights that are all zero")
        max_bits = total.bit_length()
        left = (1 << max_bits) - total
        if left & (left - 1):
            raise ZstdError("Huffman weights that do not complete a tree")
        weights = [*weights, left.bit_length()]
        if max_bits > 11:
            raise ZstdError("a Huffman code longer than 11 bits")
        lengths = [max_bits + 1 - w if w > 0 else 0 for w in weights]
        size = 1 << max_bits
        ranks = [0] * (max_bits + 1)
        for length in lengths:
            if length:
                ranks[length] += 1
        start = [0] * (max_bits + 2)
        self.bits = [0] * size
        for length in range(max_bits, 0, -1):
            start[length - 1] = start[length] + ranks[length] * (1 << (max_bits - length))
            for i in range(start[length], start[length - 1]):
                self.bits[i] = length
        self.symbols = [0] * size
        for symbol, length in enumerate(lengths):
            if length:
                span = 1 << (max_bits - length)
                code = start[length]
                self.symbols[code : code + span] = [symbol] * span
                start[length] += span
        self.max_bits = max_bits

    @staticmethod
    def description(data: bytes, position: int) -> tuple[Huffman, int]:
        header = data[position]
        position += 1
        if header >= 128:
            count = header - 127
            packed = data[position : position + (count + 1) // 2]
            if len(packed) * 2 < count:
                raise ZstdError("Huffman weights past the end of their block")
            direct = [w for byte in packed for w in (byte >> 4, byte & 15)][:count]
            return Huffman(direct), position + (count + 1) // 2
        table, start = Fse.header(data, position, 6, 256)
        stream = Backward(data[start : position + header])
        symbols = table.symbols
        state1, state2 = stream.read(table.accuracy), stream.read(table.accuracy)
        weights: list[int] = []
        while len(weights) < 255:
            weights.append(symbols[state1])
            state1 = table.base[state1] + stream.read(table.bits[state1])
            if stream.offset < 0:
                weights.append(symbols[state2])
                break
            weights.append(symbols[state2])
            state2 = table.base[state2] + stream.read(table.bits[state2])
            if stream.offset < 0:
                weights.append(symbols[state1])
                break
        return Huffman(weights), position + header

    def decode(self, data: bytes, size: int) -> bytes:
        stream = Backward(data)
        bits, symbols, max_bits = self.bits, self.symbols, self.max_bits
        mask = (1 << max_bits) - 1
        state = stream.read(max_bits)
        out = bytearray()
        while stream.offset > -max_bits:
            out.append(symbols[state])
            length = bits[state]
            state = ((state << length) + stream.read(length)) & mask
        if stream.offset != -max_bits or len(out) != size:
            raise ZstdError("a Huffman stream of the wrong length")
        return bytes(out)


class Sequences:
    """The fixed parts of sequence decoding (RFC 8878 3.1.1.3.2): codes, baselines, extra bits,
    and the predefined distributions."""

    LL_BASE: ClassVar[tuple[int, ...]] = (
        *range(16),
        16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
        32768, 65536,
    )  # fmt: skip
    LL_BITS: ClassVar[tuple[int, ...]] = (
        *(0,) * 16, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    )  # fmt: skip
    ML_BASE: ClassVar[tuple[int, ...]] = (
        *range(3, 35),
        35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387,
        32771, 65539,
    )  # fmt: skip
    ML_BITS: ClassVar[tuple[int, ...]] = (
        *(0,) * 32, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    )  # fmt: skip
    LL_DEFAULT: ClassVar[list[int]] = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ]  # fmt: skip
    ML_DEFAULT: ClassVar[list[int]] = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ]  # fmt: skip
    OF_DEFAULT: ClassVar[list[int]] = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
    ]  # fmt: skip
    #: (predefined counts, its accuracy log, the largest accuracy log allowed, symbols allowed)
    KINDS: ClassVar[dict[str, tuple[list[int], int, int, int]]] = {
        "ll": (LL_DEFAULT, 6, 9, 36),
        "of": (OF_DEFAULT, 5, 8, 32),
        "ml": (ML_DEFAULT, 6, 9, 53),
    }


class Frame:
    """One frame's decoding state: its window of output, repeat offsets, and the tables a later
    block may repeat."""

    def __init__(self, window: int) -> None:
        self.window = window
        self.history = bytearray()
        self.offsets = [1, 4, 8]
        self.huffman: Huffman | None = None
        self.tables: dict[str, Fse | None] = {"ll": None, "of": None, "ml": None}

    def literals(self, block: bytes) -> tuple[bytes, int]:
        kind, size_format = block[0] & 3, (block[0] >> 2) & 3
        if kind < 2:
            if size_format in (0, 2):
                size, start = block[0] >> 3, 1
            elif size_format == 1:
                size, start = (block[0] >> 4) + (block[1] << 4), 2
            else:
                size, start = (block[0] >> 4) + (block[1] << 4) + (block[2] << 12), 3
            if kind == 0:
                if start + size > len(block):
                    raise ZstdError("raw literals past the end of their block")
                return block[start : start + size], start + size
            if start >= len(block):
                raise ZstdError("RLE literals past the end of their block")
            return bytes([block[start]]) * size, start + 1
        width, start, streams = {0: (10, 3, 1), 1: (10, 3, 4), 2: (14, 4, 4), 3: (18, 5, 4)}[
            size_format
        ]
        header = int.from_bytes(block[:start], "little")
        size = (header >> 4) & ((1 << width) - 1)
        compressed = (header >> (4 + width)) & ((1 << width) - 1)
        end = start + compressed
        if end > len(block) or size > MAX_BLOCK:
            raise ZstdError("compressed literals past the end of their block")
        position = start
        if kind == 2:
            self.huffman, position = Huffman.description(block, start)
        if self.huffman is None:
            raise ZstdError("treeless literals with no earlier Huffman table")
        if streams == 1:
            return self.huffman.decode(block[position:end], size), end
        jumps = block[position : position + 6]
        sizes = [int.from_bytes(jumps[i : i + 2], "little") for i in (0, 2, 4)]
        position += 6
        sizes.append(end - position - sum(sizes))
        if sizes[3] < 1:
            raise ZstdError("a jump table past the end of its literals")
        each = (size + 3) // 4
        out = bytearray()
        for i, length in enumerate(sizes):
            want = each if i < 3 else size - 3 * each
            out += self.huffman.decode(block[position : position + length], want)
            position += length
        return bytes(out), end

    def table(self, kind: str, mode: int, block: bytes, position: int) -> tuple[Fse, int]:
        counts, accuracy, max_accuracy, max_symbols = Sequences.KINDS[kind]
        if mode == 0:
            table = Fse(counts, accuracy)
        elif mode == 1:
            if position >= len(block):
                raise ZstdError("an RLE table past the end of its block")
            table, position = Fse.rle(block[position]), position + 1
        elif mode == 2:
            table, position = Fse.header(block, position, max_accuracy, max_symbols)
        else:
            previous = self.tables[kind]
            if previous is None:
                raise ZstdError("a repeated table with no earlier table")
            table = previous
        self.tables[kind] = table
        return table, position

    def offset(self, value: int, literal_length: int) -> int:
        history = self.offsets
        if value > 3:
            offset = value - 3
            history[2], history[1], history[0] = history[1], history[0], offset
            return offset
        index = value - 1 + (literal_length == 0)
        if index == 0:
            return history[0]
        offset = history[index] if index < 3 else history[0] - 1
        if offset == 0:
            raise ZstdError("a repeat offset of zero")
        if index > 1:
            history[2] = history[1]
        history[1], history[0] = history[0], offset
        return offset

    def compressed(self, block: bytes) -> bytes:
        literals, position = self.literals(block)
        if position >= len(block):
            raise ZstdError("a block with no sequences section")
        first = block[position]
        if first == 0:
            count, position = 0, position + 1
        elif first < 128:
            count, position = first, position + 1
        elif first < 255:
            count, position = ((first - 128) << 8) + block[position + 1], position + 2
        else:
            count = block[position + 1] + (block[position + 2] << 8) + 0x7F00
            position += 3
        out = self.history
        begin = len(out)
        if count == 0:
            out += literals
            return bytes(out[begin:])
        modes = block[position]
        position += 1
        if modes & 3:
            raise ZstdError("reserved bits set in the compression modes")
        ll, position = self.table("ll", modes >> 6, block, position)
        of, position = self.table("of", (modes >> 4) & 3, block, position)
        ml, position = self.table("ml", (modes >> 2) & 3, block, position)
        stream = Backward(block[position:])
        ll_state, of_state, ml_state = (
            stream.read(ll.accuracy),
            stream.read(of.accuracy),
            stream.read(ml.accuracy),
        )
        ll_base, ll_bits, ml_base, ml_bits = (
            Sequences.LL_BASE,
            Sequences.LL_BITS,
            Sequences.ML_BASE,
            Sequences.ML_BITS,
        )
        used = 0
        for left in range(count - 1, -1, -1):
            of_code, ll_code, ml_code = (
                of.symbols[of_state],
                ll.symbols[ll_state],
                ml.symbols[ml_state],
            )
            if of_code > 31 or ll_code > 35 or ml_code > 52:
                raise ZstdError("a sequence code beyond the table")
            value = (1 << of_code) + stream.read(of_code)
            match_length = ml_base[ml_code] + stream.read(ml_bits[ml_code])
            literal_length = ll_base[ll_code] + stream.read(ll_bits[ll_code])
            if left:
                ll_state = ll.base[ll_state] + stream.read(ll.bits[ll_state])
                ml_state = ml.base[ml_state] + stream.read(ml.bits[ml_state])
                of_state = of.base[of_state] + stream.read(of.bits[of_state])
            offset = self.offset(value, literal_length)
            if used + literal_length > len(literals):
                raise ZstdError("a sequence past the end of its literals")
            out += literals[used : used + literal_length]
            used += literal_length
            if offset > len(out) or offset > self.window:
                raise ZstdError("a match before the start of the window")
            if offset >= match_length:
                start = len(out) - offset
                out += out[start : start + match_length]
            else:
                pattern = bytes(out[-offset:])
                out += (pattern * (match_length // offset + 1))[:match_length]
        if stream.offset != 0:
            raise ZstdError("a sequences bitstream not read to its end")
        out += literals[used:]
        return bytes(out[begin:])

    def keep(self) -> None:
        """Drop output older than the window; it can no longer be matched."""
        if len(self.history) > 2 * self.window + MAX_BLOCK:
            del self.history[: len(self.history) - self.window]


class Zstd:
    @staticmethod
    def frames(data: bytes | IO[bytes], limit: int | None = None) -> Iterator[bytes]:
        """The decompressed content of every frame in `data` -- bytes, or a stream read as it is
        needed -- a block at a time; with a `limit`, fails once more than that has come out.
        Malformed data is a `ZstdError`, whatever part of the format it breaks."""
        try:
            yield from Zstd._frames(_Input(data), limit)
        except (IndexError, KeyError) as exc:
            raise ZstdError("data cut short or out of range") from exc

    @staticmethod
    def _frames(src: _Input, limit: int | None) -> Iterator[bytes]:
        produced = 0
        while not src.at_end():
            if src.left() < 4:
                raise ZstdError("trailing bytes after the last frame")
            magic = int.from_bytes(src.take(4, "a frame magic"), "little")
            if magic & 0xFFFFFFF0 == 0x184D2A50:
                size = int.from_bytes(src.take(4, "a skippable frame size"), "little")
                src.skip(size, "a skippable frame")
                continue
            if magic != MAGIC:
                raise ZstdError("not a zstd frame")
            descriptor = src.take(1, "a frame header")[0]
            fcs_flag, single, checksum, dict_flag = (
                descriptor >> 6,
                (descriptor >> 5) & 1,
                (descriptor >> 2) & 1,
                descriptor & 3,
            )
            if descriptor & 8:
                raise ZstdError("a reserved frame header bit is set")
            window = 0
            if not single:
                byte = src.take(1, "a window descriptor")[0]
                exponent, mantissa = byte >> 3, byte & 7
                base = 1 << (10 + exponent)
                window = base + (base >> 3) * mantissa
            dict_size = (0, 1, 2, 4)[dict_flag]
            if int.from_bytes(src.take(dict_size, "a dictionary id"), "little"):
                raise ZstdError("a frame that needs a dictionary")
            fcs_size = (1 if single else 0, 2, 4, 8)[fcs_flag]
            content = int.from_bytes(src.take(fcs_size, "a content size"), "little")
            if fcs_size == 2:
                content += 256
            if single:
                window = content
            if window > MAX_WINDOW:
                raise ZstdError("a window beyond the limit")
            frame = Frame(max(window, 1))
            hasher = XXH64Stream() if checksum else None
            while True:
                header = int.from_bytes(src.take(3, "a block header"), "little")
                last, kind, size = header & 1, (header >> 1) & 3, header >> 3
                if kind == 1:
                    out = src.take(1, "an RLE block") * size
                    frame.history += out
                elif kind == 3:
                    raise ZstdError("a reserved block type")
                else:
                    if size > MAX_BLOCK:
                        raise ZstdError("a block larger than the format allows")
                    body = src.take(size, "a block")
                    if kind == 0:
                        out = body
                        frame.history += out
                    else:
                        out = frame.compressed(body)
                produced += len(out)
                if limit is not None and produced > limit:
                    raise ZstdError("decompressed data beyond the limit")
                if hasher is not None:
                    hasher.update(out)
                frame.keep()
                yield out
                if last:
                    break
            if hasher is not None:
                expected = int.from_bytes(src.take(4, "a content checksum"), "little")
                if hasher.digest() & 0xFFFFFFFF != expected:
                    raise ZstdError("a frame whose content checksum does not match")

    @staticmethod
    def decompress(data: bytes, limit: int | None = None) -> bytes:
        return b"".join(Zstd.frames(data, limit))

    class Reader(io.RawIOBase):
        """`frames` as a readable stream."""

        def __init__(self, data: bytes | IO[bytes], limit: int | None = None) -> None:
            self.blocks: Any = Zstd.frames(data, limit)
            self.pending = b""

        def readable(self) -> bool:
            return True

        def readinto(self, buffer: Any) -> int:
            while not self.pending:
                self.pending = next(self.blocks, b"")
                if not self.pending:
                    return 0
            count = min(len(buffer), len(self.pending))
            buffer[:count] = self.pending[:count]
            self.pending = self.pending[count:]
            return count
