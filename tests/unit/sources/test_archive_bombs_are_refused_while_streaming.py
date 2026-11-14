"""Bombs are stopped while the bytes are produced, not after (`package.md` PK-02, PK-03)."""

from __future__ import annotations

import bz2
import gzip
import io
import struct
import tarfile
import time

import pytest

from cordon_scanner.foundation.limits import DEFAULT_LIMITS, Limits
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import Rejection
from support import PeakMemory


class DeclaredKit:
    """Zero-filled data in formats that declare their own size, small enough for a unit test:
    gzip makes each a thousandfold expansion, as the masks and volumes in 05-CENSUS C2 are."""

    # Identical-block metering off: these tests are about the expansion cap and the declared-size
    # exception themselves; test_identical_block_runs.py covers the metering.
    LIMITS = Limits(
        max_member_bytes=64 * 1024,
        max_archive_ratio=10,
        max_elided_member_bytes=0,
        max_elided_bytes=0,
    )

    @staticmethod
    def fits(width: int, height: int, *, pad: bytes = b"", header_fill: bytes = b" ") -> bytes:
        cards = [
            "SIMPLE  =                    T",
            "BITPIX  =                    8",
            "NAXIS   =                    2",
            f"NAXIS1  = {width:>20}",
            f"NAXIS2  = {height:>20}",
            "END",
        ]
        header = b"".join(c.ljust(80).encode() for c in cards)
        header += header_fill * (-len(header) % 2880)
        data = b"\0" * (width * height)
        slack = -len(data) % 2880
        tail = (pad + b"\0" * slack)[:slack] if slack else b""
        return header + data + tail

    @staticmethod
    def nifti(shape: tuple[int, ...], *, extension: bytes = b"\0\0\0\0") -> bytes:
        header = bytearray(348)
        struct.pack_into("<i", header, 0, 348)
        dims = (len(shape), *shape) + (1,) * (7 - len(shape))
        struct.pack_into("<8h", header, 40, *dims)
        struct.pack_into("<h", header, 72, 8)
        struct.pack_into("<f", header, 108, 352.0)
        header[344:348] = b"n+1\0"
        voxels = 1
        for d in shape:
            voxels *= d
        return bytes(header) + extension + b"\0" * voxels

    @staticmethod
    def ntfs(sectors: int) -> bytes:
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        struct.pack_into("<H", boot, 11, 512)
        struct.pack_into("<Q", boot, 0x28, sectors)
        boot[510:512] = b"\x55\xaa"
        return bytes(boot) + b"\0" * (sectors * 512)

    @staticmethod
    def read(plain: bytes, name: str, limits: Limits | None = None, *, gz: bytes | None = None):
        data = gz if gz is not None else gzip.compress(plain, compresslevel=9)
        return ArchiveReader.extract(data, path=name, limits=limits or DeclaredKit.LIMITS)

    @staticmethod
    def padded(result) -> bool:
        return any(r.reason == Rejection.PADDED for r in result.rejected)


class TestAFormatThatDeclaresItsSizeMayExpandToIt:
    """08-BENIGN-F-SHAPES 7c: an expansion the stream's own format declares, exactly, is read like
    any member; anything else stays padding."""

    @pytest.mark.parametrize(
        ("name", "plain"),
        [
            pytest.param("mask.fits.gz", DeclaredKit.fits(2048, 512), id="FITS"),
            pytest.param("vol.nii.gz", DeclaredKit.nifti((64, 64, 64, 4)), id="NIfTI-1"),
            pytest.param("disk.img.gz", DeclaredKit.ntfs(2048), id="NTFS"),
        ],
    )
    def test_read_to_its_end_when_its_header_declares_exactly_what_it_expands_to(
        self, name: str, plain: bytes
    ) -> None:
        result = DeclaredKit.read(plain, name)
        assert not DeclaredKit.padded(result), result.rejected
        assert [len(m.data) for m in result.members] == [len(plain)]

    def test_the_same_zeros_with_no_such_header_are_still_padding(self) -> None:
        assert DeclaredKit.padded(DeclaredKit.read(b"\0" * 1_048_576, "blob.bin.gz"))

    def test_a_declared_size_one_block_off_is_padding(self) -> None:
        plain = DeclaredKit.fits(2048, 512) + b"\0" * 2880  # a block past what the header says
        assert DeclaredKit.padded(DeclaredKit.read(plain, "mask.fits.gz"))

    def test_more_than_one_gzip_member_is_padding(self) -> None:
        plain = DeclaredKit.fits(2048, 512)
        gz = gzip.compress(plain) + gzip.compress(b"\0" * 2880)
        assert DeclaredKit.padded(DeclaredKit.read(plain, "mask.fits.gz", gz=gz))

    def test_a_declared_size_over_the_stream_limit_is_padding(self) -> None:
        limits = Limits(
            max_member_bytes=64 * 1024,
            max_archive_ratio=10,
            max_stream_bytes=512 * 1024,
            max_elided_member_bytes=0,
            max_elided_bytes=0,
        )
        assert DeclaredKit.padded(
            DeclaredKit.read(DeclaredKit.fits(2048, 512), "m.fits.gz", limits)
        )

    @pytest.mark.parametrize(
        ("name", "plain"),
        [
            pytest.param(
                "mask.fits.gz", DeclaredKit.fits(1000, 1000, pad=b"payload"), id="FITS data padding"
            ),
            pytest.param(
                "mask.fits.gz",
                DeclaredKit.fits(2048, 512, header_fill=b"x"),
                id="FITS header padding",
            ),
            pytest.param(
                "vol.nii.gz",
                DeclaredKit.nifti((64, 64, 64, 4), extension=b"\x01\0\0\0"),
                id="NIfTI extension bytes",
            ),
        ],
    )
    def test_bytes_in_the_formats_padding_are_padding(self, name: str, plain: bytes) -> None:
        """The size matches, so only the padding can carry anything: it must be empty (cordon-47)."""
        assert DeclaredKit.padded(DeclaredKit.read(plain, name))


class TestBombsAreRefusedWhileStreaming:
    def test_a_small_gzip_that_expands_to_gigabytes_is_refused_early(self) -> None:
        pytest.importorskip("resource")  # memory accounting is POSIX-only
        zeros = b"\0" * (10 * 1024 * 1024 - 1)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as archive:
            for i in range(60):
                info = tarfile.TarInfo(f"pkg/d{i}.bin")
                info.size = len(zeros)
                archive.addfile(info, io.BytesIO(zeros))
        before = PeakMemory.kib()
        result = ArchiveReader.extract(buf.getvalue(), path="bomb.tgz")
        grown_kb = PeakMemory.kib() - before
        assert grown_kb < 300 * 1024, "the expansion stopped before it was held in memory"
        assert result.truncated
        assert any(r.reason == Rejection.PADDED for r in result.rejected)

    def test_a_member_refused_by_its_declared_size_is_not_decompressed_through(self) -> None:
        info = tarfile.TarInfo("huge.bin")
        info.size = 4 * 1024**3
        compressor = bz2.BZ2Compressor(9)
        parts = [compressor.compress(info.tobuf(format=tarfile.GNU_FORMAT))]
        chunk = b"\0" * (64 * 1024 * 1024)
        for _ in range(info.size // len(chunk)):
            parts.append(compressor.compress(chunk))
        parts.append(compressor.flush())
        # CPU time: the work runs in this process, so a loaded machine does not stretch it.
        started = time.process_time()
        result = ArchiveReader.extract(b"".join(parts), path="skip.tar.bz2")
        assert time.process_time() - started < 2.0
        assert not result.members
        assert any(r.reason == Rejection.PADDED for r in result.rejected)

    def test_the_uncompressed_budget_is_below_the_memory_limit(self) -> None:
        assert DEFAULT_LIMITS.max_uncompressed_bytes < DEFAULT_LIMITS.max_memory_bytes

    def test_an_ordinary_package_is_still_read(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            data = b"module.exports = 1;\n"
            info = tarfile.TarInfo("package/index.js")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        result = ArchiveReader.extract(buf.getvalue(), path="p.tgz")
        assert [m.name for m in result.members] == ["package/index.js"]
