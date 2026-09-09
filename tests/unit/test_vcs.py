"""What recent history says, and what happens when it cannot be read.

Recency is the whole contribution here, and it is deliberately a weak signal:
the checks are worthless applied to every hook and every binary in a mature
repository, and useful applied to the handful that changed. So the tests are
mostly about the boundary -- what is recent, what is not, and what is reported
when the history is unavailable.
"""

from __future__ import annotations

import subprocess

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect.base import RepositoryUnit, ScanContext
from cordon_scanner.detect.vcs import VcsDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet


def git(root, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(root)},
    )


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init", "-q", ".")
    git(tmp_path, "config", "user.email", "t@example.invalid")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def rule_ids(root) -> list[str]:
    return [f.rule_id for f in Scanner().scan(root).findings]


class TestRecentChanges:
    def test_a_hook_added_recently_is_reported(self, repository) -> None:
        hooks = repository / ".githooks"
        hooks.mkdir()
        (hooks / "pre-commit").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        git(repository, "add", "-A")
        git(repository, "commit", "-qm", "add hook")
        assert "SUSPECT.VCS.HOOK_ADDED.001" in rule_ids(repository)

    def test_a_binary_added_recently_is_noted(self, repository) -> None:
        (repository / "helper.so").write_bytes(b"\x7fELF\x02\x01\x01\x00")
        git(repository, "add", "-A")
        git(repository, "commit", "-qm", "add helper")
        assert "POLICY.VCS.BINARY_ADDED.001" in rule_ids(repository)

    def test_an_ordinary_repository_reports_nothing(self, repository) -> None:
        assert not [r for r in rule_ids(repository) if r.endswith((".VCS.HOOK_ADDED.001",))]


class TestItActuallyRuns:
    """The gap this detector was written into.

    `RepositoryUnit` was declared and nothing produced one, and `is_git` was
    declared and nothing set it. Either alone means a repository-scoped
    detector is shipped and never executed -- which is indistinguishable, in
    the output, from one that ran and found nothing.
    """

    def test_the_inventory_knows_it_is_a_repository(self, repository) -> None:
        result = Scanner().scan(repository)
        assert result.repository is not None
        assert result.repository.is_git is True

    def test_a_plain_directory_is_not_a_repository(self, tmp_path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = Scanner().scan(tmp_path)
        assert result.repository is not None
        assert result.repository.is_git is False


class TestUnreadableHistory:
    def test_a_failure_to_read_history_is_reported(self, repository, monkeypatch) -> None:
        """A scan that could not read the history and a scan that read it and
        found nothing must not look the same."""

        def explode(root: str):
            raise OSError("no history here")

        monkeypatch.setattr(VcsDetector, "recent_paths", staticmethod(explode))

        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            repository=Scanner().scan(repository).repository,
        )
        assert ctx.repository is not None
        findings = list(VcsDetector().inspect(RepositoryUnit(repository=ctx.repository), ctx))
        assert [f.rule_id for f in findings] == ["OPERATIONAL.VCS.UNREADABLE.001"]

    def test_that_report_survives_a_severity_threshold(self, repository, monkeypatch) -> None:
        """It describes the scan rather than the code, so a reporting threshold
        must not be able to hide it."""

        def explode(root: str):
            raise OSError("no history here")

        monkeypatch.setattr(VcsDetector, "recent_paths", staticmethod(explode))
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            repository=Scanner().scan(repository).repository,
        )
        assert ctx.repository is not None
        findings = list(VcsDetector().inspect(RepositoryUnit(repository=ctx.repository), ctx))
        assert findings[0].always_report is True
