"""A `.conda` package is read when a zstd decoder exists, and reported unread when not (review 98,
REC-8): never passed as clean."""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.archive.safe import ZSTD_MAGIC, ArchiveReader
from cordon_scanner.core.config import Config

HAS_DECODER = bool(
    importlib.util.find_spec("compression.zstd")
    if importlib.util.find_spec("compression")
    else None
) or bool(importlib.util.find_spec("zstandard"))


class CondaKit:
    @staticmethod
    def package(tmp_path: Path) -> Path:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("metadata.json", '{"conda_pkg_format_version": 2}')
            archive.writestr("pkg-demo-1.0-0.tar.zst", ZSTD_MAGIC + b"\x00" * 64)
            archive.writestr("info-demo-1.0-0.tar.zst", ZSTD_MAGIC + b"\x00" * 64)
        target = tmp_path / "demo-1.0-0.conda"
        target.write_bytes(buffer.getvalue())
        return target


class TestCondaArchives:
    def test_the_format_is_an_archive(self) -> None:
        assert ArchiveReader.is_archive("demo-1.0-0.conda")
        assert ArchiveReader.is_archive("pkg-demo-1.0-0.tar.zst")

    @pytest.mark.skipif(HAS_DECODER, reason="a zstd decoder is installed here")
    def test_without_a_decoder_the_tarballs_are_reported_unread(self, tmp_path: Path) -> None:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(
            CondaKit.package(tmp_path)
        )
        refused = [
            f
            for f in result.findings
            if f.rule_id == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED"
            and "unsupported_compression" in f.message
        ]
        assert len(refused) == 2
        assert not result.complete and not result.content_complete
