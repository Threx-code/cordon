"""RAR 5, read in our own code (item 76): stored and compressed files are read with their CRCs held;
encryption, a damaged header, a wrong CRC, a distance past the output and a cut stream are refused; RAR
2.9 stays unopened. Every archive is built here by a minimal writer (literals and matches under
canonical tables), from inert text."""

from __future__ import annotations

import struct
import zlib

import pytest

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection
from cordon_scanner.sources.signatures import ArchiveSignatures, UnopenedFormats


class BitWriter:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def put(self, value: int, count: int) -> None:
        self.bits.extend((value >> (count - 1 - i)) & 1 for i in range(count))

    def data(self) -> bytes:
        padded = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(int("".join(map(str, padded[i : i + 8])), 2) for i in range(0, len(padded), 8))


class RarKit:
    """Literals and matches with fixed lengths: literals and match slots 9 bits, distance slots 2."""

    @staticmethod
    def vint(value: int) -> bytes:
        out = bytearray()
        while True:
            byte, value = value & 0x7F, value >> 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    @staticmethod
    def header(kind: int, fields: bytes, flags: int = 0, data_size: int | None = None) -> bytes:
        body = RarKit.vint(kind) + RarKit.vint(flags | (0x02 if data_size is not None else 0))
        if data_size is not None:
            body += RarKit.vint(data_size)
        body += fields
        sized = RarKit.vint(len(body)) + body
        return struct.pack("<I", zlib.crc32(sized)) + sized

    @staticmethod
    def codes(lengths: list[int]) -> dict[int, tuple[int, int]]:
        """Canonical codes, the decoder's assignment: by length, then by symbol."""
        out, code = {}, 0
        for length in range(1, 16):
            for symbol, n in enumerate(lengths):
                if n == length:
                    out[symbol] = (code, length)
                    code += 1
            code <<= 1
        return out

    @staticmethod
    def stream(ops: list[tuple[str, int, int]]) -> bytes:
        """One block with tables: ("lit", byte, 0) or ("match", length 2..9, distance 1..4)."""
        ld = [9 if s < 256 or 262 <= s < 270 else 0 for s in range(306)]
        dd = [2 if s < 4 else 0 for s in range(64)]
        table = ld + dd + [0] * 16 + [0] * 44
        bc_lengths = [5] * 20
        bc = RarKit.codes(bc_lengths)
        lc, dc = RarKit.codes(ld), RarKit.codes(dd)
        body = BitWriter()
        for n in bc_lengths:
            body.put(n, 4)
        for n in table:
            code, length = bc[n]
            body.put(code, length)
        for kind, a, b in ops:
            if kind == "lit":
                body.put(*lc[a])
            else:
                body.put(*lc[262 + (a - 2)])  # length slot a-2 (< 8): no extra bits
                body.put(*dc[b - 1])  # distance slot b-1 (< 4): distance b
        payload = body.data()
        bitsize = (len(body.bits) - 1) % 8 + 1
        size = len(payload)
        flags = 0x80 | 0x40 | (bitsize - 1) | (1 << 3)  # tables, last block, 2-byte size
        sizes = bytes([size & 0xFF, size >> 8])
        check = (0x5A ^ flags ^ size ^ (size >> 8)) & 0xFF
        return bytes([flags, check]) + sizes + payload

    @staticmethod
    def archive(files: dict[str, tuple[bytes, bytes | None]], *, encrypted: bool = False) -> bytes:
        """`files`: name → (content, the compressed stream or None to store it)."""
        out = b"Rar!\x1a\x07\x01\x00" + RarKit.header(1, RarKit.vint(0))
        if encrypted:
            out += RarKit.header(4, RarKit.vint(0) + RarKit.vint(0))
        for name, (content, packed) in files.items():
            data = content if packed is None else packed
            method = 0 if packed is None else 3
            info = (method << 7) | (0 << 10)
            raw = name.encode()
            fields = (
                RarKit.vint(0x04)
                + RarKit.vint(len(content))
                + RarKit.vint(0)
                + struct.pack("<I", zlib.crc32(content))
                + RarKit.vint(info)
                + RarKit.vint(1)
                + RarKit.vint(len(raw))
                + raw
            )
            out += RarKit.header(2, fields, data_size=len(data)) + data
        return out + RarKit.header(5, RarKit.vint(0))

    @staticmethod
    def read(data: bytes) -> tuple[dict[str, bytes], list[str]]:
        result = ArchiveReader.extract(data, path="pkg.rar", limits=DEFAULT_LIMITS)
        return {m.name: bytes(m.data) for m in result.members}, [r.reason for r in result.rejected]


TEXT = b"plain words, plain words\n"


class TestRar5:
    def test_a_stored_file_is_read(self) -> None:
        members, rejected = RarKit.read(RarKit.archive({"docs/a.txt": (TEXT, None)}))
        assert members == {"docs/a.txt": TEXT} and not rejected

    def test_a_compressed_file_is_decoded(self) -> None:
        """Literals, then matches copying back: "abcabcabcab" from three literals."""
        ops = [("lit", ord("a"), 0), ("lit", ord("b"), 0), ("lit", ord("c"), 0), ("match", 8, 3)]
        content = b"abcabcabcab"
        members, _ = RarKit.read(RarKit.archive({"x.txt": (content, RarKit.stream(ops))}))
        assert members == {"x.txt": content}

    def test_it_is_an_archive_by_its_main_header_not_its_magic(self) -> None:
        data = RarKit.archive({"a.txt": (TEXT, None)})
        assert ArchiveSignatures.opens(data)
        assert not ArchiveSignatures.opens(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 40)

    def test_a_crc_that_does_not_hold_is_refused(self) -> None:
        ops = [("lit", ord("a"), 0), ("lit", ord("b"), 0)]
        with pytest.raises(ArchiveError, match="CRC"):
            RarKit.read(
                RarKit.archive({"x.txt": (b"ax", RarKit.stream(ops))})
            )  # it decodes to "ab"

    def test_a_distance_past_the_output_is_refused(self) -> None:
        ops = [("lit", ord("a"), 0), ("match", 4, 4)]
        with pytest.raises(ArchiveError, match="distance"):
            RarKit.read(RarKit.archive({"x.txt": (b"aaaaa", RarKit.stream(ops))}))

    def test_a_cut_stream_is_refused(self) -> None:
        ops = [("lit", ord("a"), 0)]
        with pytest.raises(ArchiveError):
            RarKit.read(RarKit.archive({"x.txt": (b"a" * 50, RarKit.stream(ops))}))

    def test_an_encrypted_archive_is_refused(self) -> None:
        with pytest.raises(ArchiveError, match="encrypted"):
            RarKit.read(RarKit.archive({"a.txt": (TEXT, None)}, encrypted=True))

    def test_a_damaged_header_is_refused(self) -> None:
        data = bytearray(RarKit.archive({"a.txt": (TEXT, None)}))
        data[20] ^= 0xFF
        with pytest.raises(ArchiveError):
            RarKit.read(bytes(data))

    def test_rar_2_9_stays_unopened_and_said(self) -> None:
        old = b"Rar!\x1a\x07\x00" + b"\x00" * 64
        rejected: list[tuple[str, str, str]] = []
        assert UnopenedFormats.refused("pkg.tgz!old.rar", old, rejected)
        assert [r[1] for r in rejected] == [Rejection.UNSUPPORTED_FORMAT]
        assert "no reader here opens" in rejected[0][2]

    def test_a_stream_past_its_deadline_is_a_timeout(self, monkeypatch) -> None:
        """The deadline is read inside the decoder, not only between headers (modelling review,
        should-fix 5): a large member at Python speed is a timeout gap, never a worker kill."""
        from cordon_scanner.sources import rar

        monkeypatch.setattr(rar._Unpack, "CHECK_EVERY", 1)
        unpack = rar._Unpack(1 << 20, deadline=0.0)
        ops = [("lit", ord("a"), 0)] * 4
        packed = RarKit.stream(ops)
        with pytest.raises(ArchiveError, match="time budget"):
            unpack.run(packed, 4)

    def test_many_tiny_blocks_still_meet_the_deadline(self) -> None:
        """The deadline is read per block too, and the symbol count spans blocks: a stream of
        blocks each far under the check interval is still a timeout (modelling review, item 5)."""
        from cordon_scanner.sources import rar

        block = RarKit.stream([("lit", ord("a"), 0)])
        flags = block[0] & ~0x40  # not the last block
        tiny = bytes([flags, (0x5A ^ flags ^ block[2] ^ block[3]) & 0xFF]) + block[2:]
        unpack = rar._Unpack(1 << 20, deadline=0.0)
        with pytest.raises(ArchiveError, match="time budget"):
            unpack.run(tiny * 50 + block, 51)
