"""Bombs are refused while the bytes are produced, not after (`package.md` PK-02, PK-03)."""

from __future__ import annotations

import bz2
import io
import resource
import tarfile
import time

import pytest

from cordon_scanner.archive.safe import ArchiveReader
from cordon_scanner.core.errors import ArchiveError
from cordon_scanner.core.limits import DEFAULT_LIMITS


class TestBombsAreRefusedWhileStreaming:
    def test_a_small_gzip_that_expands_to_gigabytes_is_refused_early(self) -> None:
        zeros = b"\0" * (10 * 1024 * 1024 - 1)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as archive:
            for i in range(60):
                info = tarfile.TarInfo(f"pkg/d{i}.bin")
                info.size = len(zeros)
                archive.addfile(info, io.BytesIO(zeros))
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        with pytest.raises(ArchiveError, match="ceiling"):
            ArchiveReader.extract(buf.getvalue(), path="bomb.tgz")
        grown_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        assert grown_kb < 300 * 1024, "the archive was refused before it was held in memory"

    def test_a_member_refused_by_its_declared_size_is_not_decompressed_through(self) -> None:
        info = tarfile.TarInfo("huge.bin")
        info.size = 4 * 1024**3
        compressor = bz2.BZ2Compressor(9)
        parts = [compressor.compress(info.tobuf(format=tarfile.GNU_FORMAT))]
        chunk = b"\0" * (64 * 1024 * 1024)
        for _ in range(info.size // len(chunk)):
            parts.append(compressor.compress(chunk))
        parts.append(compressor.flush())
        started = time.monotonic()
        with pytest.raises(ArchiveError):
            ArchiveReader.extract(b"".join(parts), path="skip.tar.bz2")
        assert time.monotonic() - started < 2.0

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
