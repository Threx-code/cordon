"""7z, read on the standard library's lzma (item 76): stored, LZMA, LZMA2 and a filter chain are read;
an encoded header is read; AES, a declared size past the budget, and a damaged header are refused.
Every archive is built here, by a minimal writer, from inert text."""

from __future__ import annotations

import lzma
import struct
import zlib

import pytest

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection
from cordon_scanner.sources.signatures import ArchiveSignatures, UnopenedFormats

COPY, LZMA2, LZMA1, DELTA, AES = b"\x00", b"\x21", b"\x03\x01\x01", b"\x03", b"\x06\xf1\x07\x01"


class SevenZipKit:
    @staticmethod
    def number(value: int) -> bytes:
        """A 7z NUMBER: a first byte whose leading ones count the little-endian bytes after it."""
        for extra in range(8):
            if value < 1 << (7 * (extra + 1)):
                first = (0xFF << (8 - extra)) & 0xFF | (value >> (8 * extra))
                return bytes([first]) + value.to_bytes(8, "little")[:extra]
        return b"\xff" + value.to_bytes(8, "little")

    @staticmethod
    def coder(method: bytes, props: bytes) -> bytes:
        flag = len(method) | (0x20 if props else 0)
        return bytes([flag]) + method + (SevenZipKit.number(len(props)) + props if props else b"")

    @staticmethod
    def streams(
        packed: bytes,
        coders: list[tuple[bytes, bytes]],
        sizes: list[int],
        files: list[int],
        crc: int | None = None,
    ) -> bytes:
        """StreamsInfo for one folder of chained coders, the first coder's output the folder's."""
        n = SevenZipKit.number
        out = b"\x06" + n(0) + n(1) + b"\x09" + n(len(packed)) + b"\x00"
        folder = n(len(coders)) + b"".join(SevenZipKit.coder(m, p) for m, p in coders)
        folder += b"".join(n(i) + n(i + 1) for i in range(len(coders) - 1))  # in i <- out i+1
        out += (
            b"\x07\x0b"
            + n(1)
            + b"\x00"
            + folder
            + b"\x0c"
            + b"".join(n(s) for s in sizes)
            + (b"\x0a\x01" + struct.pack("<I", crc) if crc is not None else b"")
            + b"\x00"
        )
        out += b"\x08\x0d" + n(len(files)) + b"\x09" + b"".join(n(s) for s in files[:-1]) + b"\x00"
        return out + b"\x00"

    @staticmethod
    def archive(
        entries: dict[str, bytes],
        method: str = "copy",
        *,
        encoded_header: bool = False,
        declared: int | None = None,
        folder_crc: int | None = None,
    ) -> bytes:
        body = b"".join(entries.values())
        size = len(body) if declared is None else declared
        if method == "copy":
            packed, coders, sizes = body, [(COPY, b"")], [size]
        elif method == "lzma2":
            packed = lzma.compress(
                body, lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}]
            )
            coders, sizes = [(LZMA2, bytes([40]))], [size]  # a 4 GB dictionary declared
        elif method == "lzma1":
            f = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}
            packed = lzma.compress(body, lzma.FORMAT_RAW, filters=[f])
            coders, sizes = (
                [(LZMA1, bytes([3 + 9 * 0 + 45 * 2]) + struct.pack("<I", 1 << 16))],
                [size],
            )
        elif method == "delta+lzma2":
            chain = [{"id": lzma.FILTER_DELTA, "dist": 2}, {"id": lzma.FILTER_LZMA2}]
            packed = lzma.compress(body, lzma.FORMAT_RAW, filters=chain)
            coders, sizes = [(DELTA, b"\x01"), (LZMA2, bytes([16]))], [size, size]
        elif method == "aes":
            packed, coders, sizes = body, [(AES, b"\x00")], [size]
        else:
            raise AssertionError(method)
        n = SevenZipKit.number
        names = b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in entries)
        files = b"\x05" + n(len(entries)) + b"\x11" + n(len(names) + 1) + b"\x00" + names + b"\x00"
        header = (
            b"\x01\x04"
            + SevenZipKit.streams(
                packed, coders, sizes, [len(v) for v in entries.values()], folder_crc
            )
            + files
            + b"\x00"
        )
        tail = packed
        if encoded_header:
            raw = lzma.compress(header, lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2}])
            tail = packed + raw
            enc = b"\x17" + SevenZipKit.streams(
                raw, [(LZMA2, bytes([16]))], [len(header)], [len(header)]
            )
            enc = enc.replace(b"\x06" + n(0), b"\x06" + n(len(packed)), 1)
            header = enc
        start = struct.pack("<QQI", len(tail), len(header), zlib.crc32(header))
        return (
            b"7z\xbc\xaf\x27\x1c\x00\x04"
            + struct.pack("<I", zlib.crc32(start))
            + start
            + tail
            + header
        )

    @staticmethod
    def read(data: bytes) -> tuple[dict[str, bytes], list[str]]:
        result = ArchiveReader.extract(data, path="pkg.7z", limits=DEFAULT_LIMITS)
        return {m.name: bytes(m.data) for m in result.members}, [r.reason for r in result.rejected]


FILES = {"docs/readme.txt": b"plain words\n" * 50, "src/index.js": b"module.exports = 1;\n" * 20}


class TestSevenZip:
    @pytest.mark.parametrize("method", ["copy", "lzma2", "lzma1", "delta+lzma2"])
    def test_its_members_are_read(self, method: str) -> None:
        members, rejected = SevenZipKit.read(SevenZipKit.archive(FILES, method))
        assert members == FILES
        assert not rejected

    def test_an_encoded_header_is_read(self) -> None:
        members, _ = SevenZipKit.read(SevenZipKit.archive(FILES, "lzma2", encoded_header=True))
        assert members == FILES

    def test_it_is_an_archive_by_its_start_header_not_its_magic(self) -> None:
        data = SevenZipKit.archive(FILES)
        assert ArchiveSignatures.opens(data)
        assert not ArchiveSignatures.opens(data[:6] + b"\x00" * 40)

    def test_aes_is_refused_by_name(self) -> None:
        with pytest.raises(ArchiveError, match="AES"):
            SevenZipKit.read(SevenZipKit.archive(FILES, "aes"))

    def test_a_declared_size_past_the_budget_is_refused_before_decoding(self) -> None:
        data = SevenZipKit.archive(FILES, declared=DEFAULT_LIMITS.max_uncompressed_bytes + 1)
        members, rejected = SevenZipKit.read(data)
        assert not members
        assert rejected == [Rejection.SIZE]

    def test_a_damaged_header_is_the_archives_error(self) -> None:
        data = bytearray(SevenZipKit.archive(FILES))
        data[-3] ^= 0xFF
        with pytest.raises(ArchiveError, match="CRC"):
            SevenZipKit.read(bytes(data))

    def test_one_that_would_not_open_stays_refused_in_a_walk(self) -> None:
        rejected: list[tuple[str, str, str]] = []
        UnopenedFormats.nested(
            "pkg.tgz!a.7z", SevenZipKit.archive(FILES, "aes"), ArchiveError("x"), rejected
        )
        assert [r[1] for r in rejected] == [Rejection.UNSUPPORTED_FORMAT]

    def test_coders_that_loop_are_refused(self) -> None:
        """Binds (0, 1), (1, 2), (2, 1): the chain from the output would loop 1 to 2 forever
        (modelling review of 2a006ecf, must-fix 1)."""
        from cordon_scanner.sources.sevenzip import SevenZipReader, _Folder

        folder = _Folder()
        folder.coders = [(LZMA2, 1, 1, b"")] * 4
        folder.binds = [(0, 1), (1, 2), (2, 1)]
        with pytest.raises(ArchiveError):
            SevenZipReader._chain(folder, "pkg.7z")

    def test_a_coder_no_chain_reaches_is_refused(self) -> None:
        from cordon_scanner.sources.sevenzip import SevenZipReader, _Folder

        folder = _Folder()
        folder.coders = [(DELTA, 1, 1, b"\x01"), (LZMA2, 1, 1, b"\x10"), (LZMA2, 1, 1, b"\x10")]
        folder.binds = [(0, 1), (2, 2)]
        with pytest.raises(ArchiveError):
            SevenZipReader._chain(folder, "pkg.7z")

    def test_a_stated_crc_that_does_not_hold_is_refused(self) -> None:
        """A folder CRC is checked against the decoded bytes (review, should-fix 6)."""
        data = SevenZipKit.archive(FILES, "lzma2", folder_crc=0xDEADBEEF)
        with pytest.raises(ArchiveError, match="CRC"):
            SevenZipKit.read(data)
