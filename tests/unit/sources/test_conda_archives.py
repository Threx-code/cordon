"""A `.conda` package is read with the core's own zstd decoder when the standard library has none
(review 98, REC-8): its tarballs are scanned, and a corrupt one is reported unread, never clean."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.sources.archive import ZSTD_MAGIC, ArchiveReader


class CondaKit:
    @staticmethod
    def zstd(data: bytes) -> bytes:
        """`data` as one zstd frame of raw blocks: what an encoder emits for incompressible input,
        written by hand because the standard library has no zstd encoder before 3.14."""
        assert 256 <= len(data) < 65536 + 256
        frame = bytearray(ZSTD_MAGIC + bytes([0x60]) + (len(data) - 256).to_bytes(2, "little"))
        blocks = [data[i : i + 65536] for i in range(0, len(data), 65536)]
        for index, block in enumerate(blocks):
            last = index == len(blocks) - 1
            frame += ((len(block) << 3) | last).to_bytes(3, "little") + block
        return bytes(frame)

    @staticmethod
    def tarball(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, body in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return buffer.getvalue()

    @staticmethod
    def package(tmp_path: Path, pkg: bytes, info: bytes) -> Path:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("metadata.json", '{"conda_pkg_format_version": 2}')
            archive.writestr("pkg-demo-1.0-0.tar.zst", pkg)
            archive.writestr("info-demo-1.0-0.tar.zst", info)
        target = tmp_path / "demo-1.0-0.conda"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def readable(tmp_path: Path) -> Path:
        pkg = CondaKit.tarball({"site-packages/demo/__init__.py": b"VERSION = '1.0'\n"})
        info = CondaKit.tarball({"info/index.json": b'{"name": "demo", "version": "1.0"}'})
        return CondaKit.package(tmp_path, CondaKit.zstd(pkg), CondaKit.zstd(info))


class TestCondaArchives:
    def test_the_format_is_an_archive(self) -> None:
        assert ArchiveReader.is_archive("demo-1.0-0.conda")
        assert ArchiveReader.is_archive("pkg-demo-1.0-0.tar.zst")

    def test_the_tarballs_inside_are_read(self, tmp_path: Path) -> None:
        conda = CondaKit.readable(tmp_path)
        rejected: list[tuple[str, str, str]] = []
        names = [
            name
            for name, _ in ArchiveReader.walk_archive(
                conda.read_bytes(), path=conda.name, rejected=rejected
            )
        ]
        assert any(name.endswith("site-packages/demo/__init__.py") for name in names)
        assert any(name.endswith("info/index.json") for name in names)
        assert not rejected

    def test_a_read_package_is_complete(self, tmp_path: Path) -> None:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(
            CondaKit.readable(tmp_path)
        )
        assert result.complete and result.content_complete
        assert not [
            f for f in result.findings if f.rule_id == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED"
        ]

    def test_a_corrupt_tarball_is_reported_unread(self, tmp_path: Path) -> None:
        corrupt = ZSTD_MAGIC + b"\x00" * 64
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(
            CondaKit.package(tmp_path, corrupt, corrupt)
        )
        assert not result.content_complete
