"""What one scan opens is not kept for the next: a long-running Scanner (the server, MCP) held every
archive's expanded members from every scan it ever ran, and reported each scan's archive counts
added to the scans before it (found in the modelling team's review of fix/folded-copies)."""

from __future__ import annotations

import io
import tarfile

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config


class PerScanKit:
    @staticmethod
    def tree_with_archive(root, name: str) -> None:
        root.mkdir()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"module.exports = 1;\n"
            info = tarfile.TarInfo("inner/index.js")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        (root / name).write_bytes(buf.getvalue())
        (root / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")


class TestOneScanIsNotKeptForTheNext:
    def test_the_expanded_archives_are_emptied_after_a_scan(self, tmp_path) -> None:
        PerScanKit.tree_with_archive(tmp_path / "a", "vendor.tgz")
        scanner = Scanner(Config.default().with_overrides(use_cache=False, offline=True))
        scanner.scan(tmp_path / "a")
        assert scanner._engine._expansions == {}

    def test_each_scan_reports_its_own_archive_counts(self, tmp_path) -> None:
        PerScanKit.tree_with_archive(tmp_path / "a", "one.tgz")
        PerScanKit.tree_with_archive(tmp_path / "b", "two.tgz")
        scanner = Scanner(Config.default().with_overrides(use_cache=False, offline=True))
        first = scanner.scan(tmp_path / "a").stats
        second = scanner.scan(tmp_path / "b").stats
        assert second.archives_expanded == first.archives_expanded == 1
        assert second.archive_members == first.archive_members
