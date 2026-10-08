"""`cordon-scanner review`: what a dependency update adds (advanced gap M8).

Offline: the graph at the base revision (read from git) against the working tree's, classified
as added, upgraded, downgraded and removed, with the advisories the new versions match and the
ones the update fixes. Online, with the registry substituted: both releases fetched, compared,
and a release that gained an install hook makes the review fail. A registry that cannot verify
its archive leaves the change listed and says it was not compared.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import zipfile

import pytest

from cordon_scanner.cli.review import ChangeReview, GraphDiff, PackageChange, ReviewReport
from cordon_scanner.core import release_diff
from cordon_scanner.core.models import Severity
from cordon_scanner.intel.more_registries import MoreRegistries
from cordon_scanner.intel.registry_client import PackageArchive, RegistryError


class ReviewHelpers:
    @staticmethod
    def lock(packages: dict[str, str]) -> str:
        entries = {f"node_modules/{n}": {"version": v} for n, v in packages.items()}
        return json.dumps(
            {
                "name": "app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0", "dependencies": dict(packages)},
                    **entries,
                },
            }
        )

    @staticmethod
    def repository(tmp_path, before: dict[str, str], after: dict[str, str]):
        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init", "-q")
        git("config", "user.email", "review@example.test")
        git("config", "user.name", "review")
        (tmp_path / "package-lock.json").write_text(ReviewHelpers.lock(before), encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "base")
        (tmp_path / "package-lock.json").write_text(ReviewHelpers.lock(after), encoding="utf-8")
        return tmp_path

    @staticmethod
    def changes(tmp_path, before, after) -> list[PackageChange]:
        (tmp_path / "repo").mkdir()
        root = ReviewHelpers.repository(tmp_path / "repo", before, after)
        base = tmp_path / "base"
        base.mkdir()
        GraphDiff.at_revision(root, "HEAD", base)
        return GraphDiff.diff(GraphDiff.graph(base), GraphDiff.graph(root))


class TestTheGraphDiff:
    def test_each_kind_of_change(self, tmp_path) -> None:
        changes = ReviewHelpers.changes(
            tmp_path,
            {"left-pad": "1.1.3", "ms": "2.0.0", "debug": "4.3.4"},
            {"ms": "2.1.3", "debug": "4.1.0", "chalk": "5.3.0"},
        )
        assert {(c.kind, c.name, c.old, c.new) for c in changes} == {
            ("removed", "left-pad", "1.1.3", None),
            ("upgraded", "ms", "2.0.0", "2.1.3"),
            ("downgraded", "debug", "4.3.4", "4.1.0"),
            ("added", "chalk", None, "5.3.0"),
        }

    def test_nothing_changed_is_nothing(self, tmp_path) -> None:
        assert ReviewHelpers.changes(tmp_path, {"ms": "2.1.3"}, {"ms": "2.1.3"}) == []

    def test_a_ref_that_reads_as_an_option_is_refused(self, tmp_path) -> None:
        from cordon_scanner.core.errors import ConfigError

        with pytest.raises(ConfigError):
            GraphDiff.at_revision(tmp_path, "--output=/tmp/x", tmp_path)


class TestAdvisories:
    def test_a_vulnerable_new_version_and_what_an_upgrade_fixes(self) -> None:
        added = PackageChange("added", "npm", "lodash", None, "4.17.20", direct=True)
        upgraded = PackageChange("upgraded", "npm", "lodash", "4.17.20", "4.17.21", direct=True)
        ChangeReview.advisories([added, upgraded])
        if not added.vulnerable:
            pytest.skip("the bundled advisory data no longer lists lodash 4.17.20")
        assert added.blocking
        # 4.17.21 fixes the command-injection advisory; a later one still matches it, and stays listed.
        assert "GHSA-35jh-r3h4-6jhm" in upgraded.fixed
        assert not set(upgraded.fixed) & {i for i, _ in upgraded.vulnerable}


class TestReleaseComparison:
    @staticmethod
    def stub(monkeypatch, *, fail: bool = False, gained_hook: bool = True) -> list[tuple[str, str]]:
        fetched: list[tuple[str, str]] = []

        def archive(ecosystem, name, version):
            if fail:
                raise RegistryError(
                    f"{ecosystem} publishes no digest for {name}@{version}; nothing to verify against"
                )
            fetched.append((name, version))
            return PackageArchive(
                ecosystem, name, version, f"{name}-{version}.tgz", b"\x1f\x8b" + b"\x00" * 30
            )

        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.package_archive", archive
        )
        changes = (
            [
                release_diff.Change(
                    release_diff.RELEASE_NEW_HOOK,
                    Severity.HIGH,
                    "package/package.json",
                    "This release runs code at install.",
                )
            ]
            if gained_hook
            else []
        )
        monkeypatch.setattr(release_diff.ReleaseDiff, "compare", lambda new, old, previous: changes)
        return fetched

    def test_both_releases_are_fetched_and_a_new_hook_blocks(self, monkeypatch) -> None:
        fetched = self.stub(monkeypatch)
        change = PackageChange("upgraded", "npm", "example", "1.0.0", "1.0.1", direct=True)
        ChangeReview.releases([change], quiet=True)
        assert fetched == [("example", "1.0.1"), ("example", "1.0.0")]
        assert change.blocking and change.release[0][0] == release_diff.RELEASE_NEW_HOOK
        assert "digests verified" in change.compared

    def test_an_unverifiable_archive_is_said_not_compared(self, monkeypatch) -> None:
        self.stub(monkeypatch, fail=True)
        change = PackageChange("upgraded", "nuget", "Example", "1.0.0", "1.0.1")
        ChangeReview.releases([change], quiet=True)
        assert change.compared.startswith("not compared:") and not change.release

    def test_composer_is_listed_and_never_fetched_unverified(self, monkeypatch) -> None:
        fetched = self.stub(monkeypatch)
        change = PackageChange("upgraded", "composer", "vendor/pkg", "1.0.0", "1.1.0")
        ChangeReview.releases([change], quiet=True)
        assert fetched == [] and "no archive digest" in change.compared


class TestTheReport:
    def test_markdown_for_a_pull_request(self) -> None:
        blocking = PackageChange(
            "added",
            "npm",
            "lodash",
            None,
            "4.17.20",
            direct=True,
            vulnerable=[("GHSA-35jh-r3h4-6jhm", "high")],
        )
        quiet = PackageChange("upgraded", "npm", "ms", "2.0.0", "2.1.3")
        text = ReviewReport.markdown([blocking, quiet], "origin/main")
        assert "1 added, 1 upgraded since `origin/main`. **1 need attention.**" in text
        assert "| added | `npm:lodash` | 4.17.20 | GHSA-35jh-r3h4-6jhm (high) |" in text


class TestGoModuleHashes:
    def test_h1_is_the_checksum_databases_hash(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("example.com/m@v1.0.0/go.mod", "module example.com/m\n")
            archive.writestr("example.com/m@v1.0.0/a.go", "package m\n")
        # dirhash.Hash1, written out: one "<sha256>  <name>" line per file, sorted by name.
        lines = "".join(
            f"{hashlib.sha256(body).hexdigest()}  {name}\n"
            for name, body in sorted(
                [
                    ("example.com/m@v1.0.0/a.go", b"package m\n"),
                    ("example.com/m@v1.0.0/go.mod", b"module example.com/m\n"),
                ]
            )
        )
        expected = "h1:" + base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()
        assert MoreRegistries.go_h1(buffer.getvalue()) == expected
