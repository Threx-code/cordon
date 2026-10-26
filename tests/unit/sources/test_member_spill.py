"""An archive member too large to hold in memory is kept on disk and read whole, never refused."""

from __future__ import annotations

import gc
import io
import os
import tarfile
import zipfile
from pathlib import Path

from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.foundation.spill import SpilledBytes
from cordon_scanner.sources.archive import ArchiveReader, Rejection

LIMITS = DEFAULT_LIMITS.merged(max_member_bytes=4096, max_file_bytes=1024)
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 9


class Archives:
    @staticmethod
    def tar(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def zip(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    @staticmethod
    def kept(archive: bytes, path: str) -> dict[str, bytes]:
        result = ArchiveReader.extract(archive, path=path, limits=LIMITS)
        return {m.name: m.data for m in result.members}

    @staticmethod
    def spilled(archive: bytes, path: str, name: str) -> SpilledBytes:
        kept = Archives.kept(archive, path)[name]
        assert isinstance(kept, SpilledBytes)
        return kept


class TestSpilled:
    def test_a_member_past_the_member_limit_is_read_whole(self) -> None:
        data = bytes(range(256)) * 40  # about 10 KB, past the 4 KB member limit
        kept = Archives.spilled(
            Archives.tar({"package/data.bin": data}), "p.tgz", "package/data.bin"
        )
        assert kept.size == len(data)
        assert kept.read_whole() == data
        assert kept == data[: LIMITS.max_file_bytes]

    def test_a_program_is_read_whole_too(self) -> None:
        program = ELF + bytes(range(256)) * 40
        kept = Archives.spilled(
            Archives.tar({"package/bin/tool": program}), "p.tgz", "package/bin/tool"
        )
        assert kept.read_whole() == program

    def test_nothing_read_whole_is_left_refused(self) -> None:
        data = bytes(range(256)) * 40
        result = ArchiveReader.extract(
            Archives.tar({"package/data.bin": data}), path="p.tgz", limits=LIMITS
        )
        assert not [r for r in result.rejected if r.name == "package/data.bin"]

    def test_a_zip_member_is_read_whole(self) -> None:
        data = os.urandom(10_000)
        kept = Archives.spilled(Archives.zip({"bin/tool.exe": data}), "p.zip", "bin/tool.exe")
        assert kept.read_whole() == data

    def test_a_member_within_memory_stays_in_memory(self) -> None:
        kept = Archives.kept(Archives.tar({"package/index.js": b"x" * 500}), "p.tgz")
        assert not isinstance(kept["package/index.js"], SpilledBytes)

    def test_the_whole_member_is_charged_to_the_archive_total(self) -> None:
        data = bytes(range(256)) * 40
        result = ArchiveReader.extract(
            Archives.tar({"package/data.bin": data}), path="p.tgz", limits=LIMITS
        )
        assert result.total_uncompressed >= len(data)


class TestCeilings:
    def test_a_zip_member_declaring_far_more_than_it_stores_is_still_refused(self) -> None:
        zeros = Archives.zip({"pad.bin": b"\x00" * 400_000})
        result = ArchiveReader.extract(zeros, path="p.zip", limits=LIMITS)
        refused = [r for r in result.rejected if r.name == "pad.bin"]
        assert refused
        assert refused[0].reason == Rejection.PADDED

    def test_the_archive_total_still_stops_a_member(self) -> None:
        limits = LIMITS.merged(max_uncompressed_bytes=5000)
        data = os.urandom(10_000)
        result = ArchiveReader.extract(Archives.zip({"big.bin": data}), path="p.zip", limits=limits)
        assert not any(m.name == "big.bin" for m in result.members)
        assert any(r.name == "big.bin" for r in result.rejected)


class TestLifetime:
    def test_the_file_is_removed_when_the_member_is_released(self) -> None:
        data = os.urandom(10_000)
        kept = Archives.spilled(Archives.zip({"bin/tool.exe": data}), "p.zip", "bin/tool.exe")
        path = kept.path
        assert Path(path).exists()
        del kept
        gc.collect()
        assert not Path(path).exists()

    def test_the_file_is_owner_only(self) -> None:
        data = os.urandom(10_000)
        kept = Archives.spilled(Archives.zip({"bin/tool.exe": data}), "p.zip", "bin/tool.exe")
        assert Path(kept.path).stat().st_mode & 0o077 == 0


class TestContent:
    def test_every_byte_is_read_through_its_windows(self) -> None:
        data = os.urandom(10_000)
        kept = Archives.spilled(Archives.zip({"bin/tool.exe": data}), "p.zip", "bin/tool.exe")
        content = FileContent.from_member("p.zip!bin/tool.exe", kept, LIMITS)
        assert content.size == len(data)
        assert content.window_source is not None
        with content.window_source.reader() as read:
            assert read(0, len(data)) == data

    def test_a_worker_given_the_kept_path_reads_the_same_content(self) -> None:
        data = os.urandom(10_000)
        kept = Archives.spilled(Archives.zip({"bin/tool.exe": data}), "p.zip", "bin/tool.exe")
        parent = FileContent.from_member("p.zip!bin/tool.exe", kept, LIMITS)
        carried = parent.carried
        assert isinstance(carried, str)
        worker = FileContent.load(Path(carried), parent.path, LIMITS)
        assert isinstance(worker, FileContent)
        assert worker.sha256 == parent.sha256
