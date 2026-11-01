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

    def test_an_archive_scan_does_not_change_the_next_directory_scan(self, tmp_path) -> None:
        # Found by the modelling team: _scanning_archive stayed True after an archive scan, so a
        # later directory scan graphed vendor.tgz's lockfile as the project's own installs.
        import json

        lock = {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {"": {"name": "app"}, "node_modules/left-pad": {"version": "1.3.0"}},
        }
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w:gz") as tar:
            data = json.dumps(lock).encode()
            info = tarfile.TarInfo("vendored/package-lock.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps({"name": "app", "dependencies": {"ms": "^2.1.3"}}), encoding="utf-8"
        )
        (project / "vendor.tgz").write_bytes(inner.getvalue())
        PerScanKit.tree_with_archive(tmp_path / "other", "x.tgz")
        config = Config.default().with_overrides(use_cache=False, offline=True)
        fresh = {d.name for d in Scanner(config).scan(project).dependencies}
        scanner = Scanner(config)
        scanner.scan(tmp_path / "other" / "x.tgz")
        after = {d.name for d in scanner.scan(project).dependencies}
        assert after == fresh

    def test_a_host_scan_empties_the_scan_caches(self, tmp_path) -> None:
        from cordon_scanner.foundation.collector import ScanCaches

        held: dict[str, str] = ScanCaches.register({})
        held["a file"] = "its bytes"
        Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan_host(tmp_path)
        assert held == {}
