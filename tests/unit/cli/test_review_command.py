"""`review`: the forms a dependency review is written in, how releases are fetched and compared, and what the command refuses (`cli/commands/review.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import cordon_scanner
from cordon_scanner.cli.commands import review
from cordon_scanner.cli.commands.review import (
    ChangeReview,
    GraphDiff,
    PackageChange,
    ReviewCommand,
    ReviewReport,
)
from cordon_scanner.detect.supply import release_diff
from cordon_scanner.foundation.errors import CordonError, ExitCode
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
from cordon_scanner.intel.registries.registry_client import RegistryError


class _Base:
    @staticmethod
    def change(**over: Any) -> PackageChange:
        base: dict[str, Any] = {
            "kind": "upgraded",
            "ecosystem": "npm",
            "name": "left",
            "old": "1.0.0",
            "new": "1.1.0",
        }
        return PackageChange(**{**base, **over})

    @staticmethod
    def archive(version: str, strength: str = "") -> PackageArchive:
        return PackageArchive("npm", "left", version, f"left-{version}.tgz", b"x", strength)


class TestReports(_Base):
    def test_no_change_is_said_in_both_forms(self) -> None:
        assert ReviewReport.text([], "main") == "no dependency changes since main"
        assert "No dependency changes since `main`" in ReviewReport.markdown([], "main")

    def test_text_lists_malware_vulnerabilities_fixes_release_lines_and_why_it_compared(
        self,
    ) -> None:
        change = self.change(
            direct=True,
            malicious=["MAL-1"],
            vulnerable=[("GHSA-x", "high")],
            fixed=[f"CVE-{n}" for n in range(10)],
            release=[("R.1", "critical", "runs a downloaded file")],
            compared="1.0.0 and 1.1.0 fetched from npm, digests verified, compared",
        )
        text = ReviewReport.text([change], "main")
        assert "1 dependency change(s) since main" in text
        assert "upgraded   npm:left 1.0.0 -> 1.1.0 (direct)  BLOCKING" in text
        assert "known malicious: MAL-1" in text
        assert "vulnerable: GHSA-x (high)" in text
        assert "fixes: CVE-0, CVE-1, CVE-2, CVE-3, CVE-4, CVE-5, CVE-6, CVE-7" in text
        assert "CVE-8" not in text
        assert "critical: runs a downloaded file" in text
        assert "(1.0.0 and 1.1.0 fetched from npm, digests verified, compared)" in text

    def test_markdown_counts_blocking_changes_and_details_what_a_release_contains(self) -> None:
        blocked = self.change(
            fixed=["CVE-1"],
            release=[("R.1", "high", "reads credentials")],
            compared="compared",
        )
        quiet = self.change(kind="added", name="right", old=None, new="2.0.0")
        text = ReviewReport.markdown([blocked, quiet], "main")
        assert "fixes 1" in text
        assert "high: R.1" in text
        assert "| added | `npm:right` | 2.0.0 | - |" in text
        assert "<summary>What the changed releases contain</summary>" in text
        assert "**npm:left** (compared)" in text
        assert "- high: reads credentials" in text
        assert text.rstrip().endswith("</details>")


class TestAdvisories(_Base):
    def test_a_removed_package_has_no_new_version_to_look_up(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registry import BundledAdvisories

        class Database:
            def matching(self, ecosystem: str, name: str, version: str | None) -> list[Any]:
                raise AssertionError("a removed package must not be matched")

        monkeypatch.setattr(BundledAdvisories, "database", staticmethod(lambda: Database()))
        removed = self.change(kind="removed", new=None)
        ChangeReview.advisories([removed])
        assert removed.malicious == [] and removed.vulnerable == []


class TestReleases(_Base):
    @pytest.fixture
    def fetched(self, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        asked: list[str] = []

        def package_archive(ecosystem: str, name: str, version: str) -> PackageArchive:
            asked.append(version)
            return self.archive(version)

        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(package_archive))
        return asked

    @pytest.fixture
    def scanned(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        """What `Scanner.scan` is given, and a scan whose active findings the test sets."""
        seen: list[Any] = []
        self.active: list[Any] = []

        class Scanner:
            def __init__(self, config: Any) -> None:
                pass

            def scan(self_, path: Path) -> Any:
                seen.append(path.name)
                return SimpleNamespace(active=self.active)

        monkeypatch.setattr(cordon_scanner, "Scanner", Scanner)
        return seen

    def test_an_ecosystem_without_a_verified_source_is_said_not_fetched(
        self, fetched: list[str]
    ) -> None:
        change = self.change(ecosystem="no-such-ecosystem")
        ChangeReview.releases([change], quiet=True)
        assert change.compared == "no verified archive source for no-such-ecosystem"
        assert fetched == []

    def test_packages_past_the_limit_are_named_as_not_compared(
        self, monkeypatch: pytest.MonkeyPatch, fetched: list[str], scanned: list[Any]
    ) -> None:
        monkeypatch.setattr(review, "MAX_FETCHED", 1)
        direct = self.change(name="a", direct=True, kind="added", old=None)
        beyond = self.change(name="b", kind="added", old=None)
        ChangeReview.releases([beyond, direct], quiet=True)
        assert direct.compared.startswith("a 1.1.0 scanned from npm")
        assert beyond.compared == "past the 1-package limit for one review"
        assert fetched == ["1.1.0"]

    def test_an_added_package_is_scanned_and_only_its_serious_findings_are_kept(
        self, fetched: list[str], scanned: list[Any]
    ) -> None:
        def finding(rule: str, severity: Severity, category: Category) -> Any:
            return SimpleNamespace(
                rule_id=rule, severity=severity, category=category, message=f"{rule} message"
            )

        self.active = [
            finding("MAL.1", Severity.CRITICAL, Category.MALICIOUS),
            finding("SUS.1", Severity.MEDIUM, Category.SUSPICIOUS),
            finding("SUS.2", Severity.LOW, Category.SUSPICIOUS),
            finding("POL.1", Severity.CRITICAL, Category.POLICY),
        ]
        added = self.change(kind="added", old=None)
        ChangeReview.releases([added], quiet=True)
        assert [r for r, _, _ in added.release] == ["MAL.1", "SUS.1"]
        assert added.categories == {"MAL.1": "malicious", "SUS.1": "suspicious"}
        assert added.compared == "left 1.1.0 scanned from npm, digest verified"
        assert fetched == ["1.1.0"]

    def test_an_upgrade_fetches_both_releases_and_reports_what_changed_between_them(
        self, monkeypatch: pytest.MonkeyPatch, fetched: list[str], scanned: list[Any]
    ) -> None:
        monkeypatch.setattr(release_diff.Profile, "of", staticmethod(lambda result: result))
        monkeypatch.setattr(
            release_diff.ReleaseDiff,
            "compare",
            staticmethod(
                lambda new, old, previous: [
                    SimpleNamespace(rule_id="DIFF.1", severity=Severity.HIGH, message=previous)
                ]
            ),
        )
        change = self.change()
        ChangeReview.releases([change], quiet=True)
        assert fetched == ["1.1.0", "1.0.0"]
        assert change.release == [("DIFF.1", "high", "left 1.0.0")]
        assert change.compared == ("1.0.0 and 1.1.0 fetched from npm, digests verified, compared")
        assert change.blocking

    def test_a_release_that_cannot_be_fetched_is_named_on_stderr_unless_quiet(
        self,
        monkeypatch: pytest.MonkeyPatch,
        scanned: list[Any],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def fail(ecosystem: str, name: str, version: str) -> PackageArchive:
            raise RegistryError("HTTP 404")

        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(fail))
        loud, silent = self.change(), self.change(name="right")
        ChangeReview.releases([loud], quiet=False)
        ChangeReview.releases([silent], quiet=True)
        assert loud.compared == "not compared: HTTP 404"
        assert silent.compared == "not compared: HTTP 404"
        assert capsys.readouterr().err == "review: npm:left: HTTP 404\n"

    def test_a_weak_check_is_named_instead_of_a_verified_digest(self) -> None:
        weak = self.archive("1.0.0", strength="git-commit")
        assert ChangeReview.verified(weak) == "checked by git-commit only"
        assert ChangeReview.verified(self.archive("1.0.0")) == "digest verified"


class TestBaseRevision(_Base):
    def test_a_base_file_over_the_size_limit_or_with_no_size_is_not_written(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from cordon_scanner.sources import git

        sizes = {"big/package.json": str(review.MAX_BASE_FILE_BYTES + 1), "gone/package.json": ""}

        class Repository:
            def __init__(self, root: Path) -> None:
                pass

            def run(self, argv: list[str], check: bool = True) -> str:
                if argv[0] == "ls-tree":
                    return "\0".join(["package.json", "big/package.json", "gone/package.json"])
                if argv[0] == "cat-file":
                    return sizes.get(argv[-1].partition(":")[2], "2")
                return "{}"

        monkeypatch.setattr(git, "GitRepository", Repository)
        written = GraphDiff.at_revision(tmp_path, "main", tmp_path / "base")
        assert written == 1
        assert (tmp_path / "base" / "package.json").read_text(encoding="utf-8") == "{}"
        assert not (tmp_path / "base" / "big").exists()


class TestCommand(_Base):
    def test_a_target_that_is_not_a_directory_is_refused(self, tmp_path: Path) -> None:
        args = argparse.Namespace(target=str(tmp_path / "nope"), base="main")
        with pytest.raises(CordonError, match="review needs a repository directory"):
            ReviewCommand.run(args)

    def test_online_review_fetches_releases_and_a_blocking_change_exits_with_findings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        blocking = self.change(malicious=["MAL-1"])
        seen: dict[str, Any] = {}
        monkeypatch.setattr(GraphDiff, "at_revision", staticmethod(lambda root, ref, into: 0))
        monkeypatch.setattr(GraphDiff, "graph", staticmethod(lambda root: {}))
        monkeypatch.setattr(GraphDiff, "diff", staticmethod(lambda old, new: [blocking]))
        monkeypatch.setattr(ChangeReview, "advisories", staticmethod(lambda changes: None))
        monkeypatch.setattr(
            ChangeReview,
            "releases",
            staticmethod(lambda changes, quiet: seen.update(quiet=quiet)),
        )
        args = argparse.Namespace(
            target=str(tmp_path), base="main", online=True, quiet=True, format="text"
        )
        assert ReviewCommand.run(args) == int(ExitCode.FINDINGS)
        assert seen == {"quiet": True}
        assert "BLOCKING" in capsys.readouterr().out
