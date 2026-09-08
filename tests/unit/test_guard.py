"""Scanner self-integrity.

Every test here is an attempt to disable the guard. A control nobody has tried
to break is a control nobody knows works, and the ways to disable a git hook are
well known and cheap: delete it, unset its executable bit, point git somewhere
else, or replace it with something that exits zero.

The manifest tests are about visibility rather than prevention. An attacker who
edits a guard can regenerate the manifest in the same commit and nothing
self-hosted can stop that. What is tested is that they cannot do it *silently*.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess

import pytest

from cordon.core.errors import SourceError
from cordon.core.guard import (
    HOOKS,
    MANIFEST_NAME,
    SHIM_MARKER,
    Guard,
    GuardStatus,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(root, *args: str) -> None:
    subprocess.run([shutil.which("git"), *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "T")
    (root / "cordon.yaml").write_text("scan:\n  severity_threshold: medium\n")
    return root


class TestInstallation:
    def test_installs_every_hook(self, repository) -> None:
        assert sorted(Guard.install_hooks(repository)) == sorted(HOOKS)
        for hook in HOOKS:
            assert (repository / ".git" / "hooks" / hook).is_file()

    @pytest.mark.skipif(
        os.name == "nt", reason="Windows has no executable bit; git runs hooks regardless"
    )
    def test_shims_are_executable(self, repository) -> None:
        """A hook without the executable bit is a hook git silently never
        runs."""
        Guard.install_hooks(repository)
        for hook in HOOKS:
            path = repository / ".git" / "hooks" / hook
            assert path.stat().st_mode & stat.S_IXUSR

    def test_verification_passes_on_every_platform(self, repository) -> None:
        """Regression: the executable-bit check ran on Windows too, where the
        bit cannot be set. `cordon guard verify` therefore failed on every
        Windows machine with a correctly installed guard -- and a verification
        that always fails is one people learn to ignore, which leaves it a
        control on no platform at all."""
        Guard.install_hooks(repository)
        report = Guard.verify(repository)
        assert report.ok, [p.detail for p in report.problems]

    def test_the_windows_branch_is_exercised_everywhere(self, repository, monkeypatch) -> None:
        """The bug shipped because the branch only ran on Windows CI. Forcing it
        here means a change to it fails on the machine that made the change,
        rather than twenty minutes later on somebody else's matrix job."""
        Guard.install_hooks(repository)
        for hook in HOOKS:
            path = repository / ".git" / "hooks" / hook
            path.chmod(path.stat().st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)

        monkeypatch.setattr(Guard, "honours_executable_bit", staticmethod(lambda: False))
        assert Guard.verify(repository).ok

    def test_the_check_still_runs_where_the_bit_is_real(self, repository, monkeypatch) -> None:
        """The skip must be narrow. On a platform with an executable bit, a hook
        without it is a hook git silently never runs."""
        Guard.install_hooks(repository)
        for hook in HOOKS:
            path = repository / ".git" / "hooks" / hook
            path.chmod(path.stat().st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)

        monkeypatch.setattr(Guard, "honours_executable_bit", staticmethod(lambda: True))
        report = Guard.verify(repository)
        if (repository / ".git" / "hooks" / "pre-commit").stat().st_mode & stat.S_IXUSR:
            pytest.skip("this filesystem does not honour the executable bit")
        assert any(p.status == GuardStatus.NOT_EXECUTABLE for p in report.problems)

    def test_shims_are_identifiable(self, repository) -> None:
        Guard.install_hooks(repository)
        for hook in HOOKS:
            content = (repository / ".git" / "hooks" / hook).read_text()
            assert SHIM_MARKER in content

    def test_shims_fail_closed(self, repository) -> None:
        """If cordon cannot run, the operation is refused rather than allowed.
        A guard that silently does nothing when it cannot run is not a guard."""
        Guard.install_hooks(repository)
        content = (repository / ".git" / "hooks" / "pre-commit").read_text()
        assert "exit 1" in content
        assert "BLOCKED" in content

    def test_pre_commit_uses_staged_mode(self, repository) -> None:
        """Reading the working tree would let a poisoned file be staged and the
        clean version restored, so the hook passes while the payload commits."""
        Guard.install_hooks(repository)
        content = (repository / ".git" / "hooks" / "pre-commit").read_text()
        assert "--staged" in content

    def test_installation_is_idempotent(self, repository) -> None:
        Guard.install_hooks(repository)
        first = (repository / ".git" / "hooks" / "pre-commit").read_text()
        Guard.install_hooks(repository)
        assert (repository / ".git" / "hooks" / "pre-commit").read_text() == first

    def test_installing_clears_a_hooks_path_override(self, repository) -> None:
        """That setting points elsewhere and wins when set, so leaving it would
        install the shims and silently never run them -- the guard reads as
        present in review while doing nothing."""
        git(repository, "config", "core.hooksPath", ".githooks")
        Guard.install_hooks(repository)
        assert Guard.verify(repository).ok

    def test_outside_a_repository_is_an_error(self, tmp_path) -> None:
        plain = tmp_path / "plain"
        plain.mkdir()
        with pytest.raises(SourceError, match="not a git repository"):
            Guard.install_hooks(plain)


class TestTamperDetection:
    """Each test disables the guard a different way."""

    def test_a_clean_installation_verifies(self, repository) -> None:
        Guard.install_hooks(repository)
        assert Guard.verify(repository).ok

    def test_a_missing_hook_is_detected(self, repository) -> None:
        Guard.install_hooks(repository)
        (repository / ".git" / "hooks" / "pre-commit").unlink()
        report = Guard.verify(repository)
        assert not report.ok
        assert any(p.status == GuardStatus.MISSING for p in report.problems)

    def test_a_replaced_hook_is_detected(self, repository) -> None:
        """Replacing the shim with something that exits zero is the cheapest
        bypass available."""
        Guard.install_hooks(repository)
        (repository / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
        report = Guard.verify(repository)
        assert any(p.status == GuardStatus.NOT_A_SHIM for p in report.problems)

    @pytest.mark.skipif(
        not Guard.honours_executable_bit(),
        reason="this platform has no executable bit for git to care about",
    )
    def test_a_non_executable_hook_is_detected(self, repository) -> None:
        Guard.install_hooks(repository)
        path = repository / ".git" / "hooks" / "pre-commit"
        path.chmod(path.stat().st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
        report = Guard.verify(repository)
        if path.stat().st_mode & stat.S_IXUSR:
            pytest.skip("this filesystem does not honour the executable bit")
        assert any(p.status == GuardStatus.NOT_EXECUTABLE for p in report.problems)

    def test_a_hooks_path_override_is_detected(self, repository) -> None:
        """The cheapest way to disable every installed shim while leaving them
        on disk, so the guard looks present and does nothing."""
        Guard.install_hooks(repository)
        git(repository, "config", "core.hooksPath", "/tmp/elsewhere")
        report = Guard.verify(repository)
        assert any(p.status == GuardStatus.HOOKS_PATH_OVERRIDE for p in report.problems)

    def test_every_problem_names_a_remedy(self, repository) -> None:
        """A verification that says something is wrong without saying what to do
        gets disabled rather than fixed."""
        report = Guard.verify(repository)  # nothing installed yet
        assert report.problems
        for problem in report.problems:
            assert problem.remediation
            assert problem.detail


class TestManifest:
    def test_records_hashes_of_guard_files(self, repository) -> None:
        manifest = Guard.write_manifest(repository)
        content = manifest.read_text()
        assert "cordon.yaml" in content
        assert Guard.sha256_of(repository / "cordon.yaml") in content

    def test_verification_passes_immediately_after_writing(self, repository) -> None:
        Guard.install_hooks(repository)
        Guard.write_manifest(repository)
        assert Guard.verify(repository).ok

    def test_an_edit_to_a_guarded_file_is_detected(self, repository) -> None:
        """The whole point. The edit cannot be prevented; it can be made
        impossible to hide."""
        Guard.install_hooks(repository)
        Guard.write_manifest(repository)
        (repository / "cordon.yaml").write_text("scan:\n  severity_threshold: critical\n")
        report = Guard.verify(repository)
        assert any(p.status == GuardStatus.TAMPERED for p in report.problems)

    def test_a_removed_guarded_file_is_detected(self, repository) -> None:
        Guard.install_hooks(repository)
        Guard.write_manifest(repository)
        (repository / "cordon.yaml").unlink()
        report = Guard.verify(repository)
        assert any(p.status == GuardStatus.TAMPERED for p in report.problems)

    def test_a_missing_manifest_is_not_a_failure(self, repository) -> None:
        """Most repositories will never create one, and reporting a missing
        optional control as a problem is how a report becomes noise."""
        Guard.install_hooks(repository)
        assert not (repository / MANIFEST_NAME).exists()
        assert Guard.verify(repository).ok

    def test_the_manifest_explains_its_own_limit(self, repository) -> None:
        """The claim has to be honest in the artefact itself, not only in the
        documentation: an attacker who edits a guard can regenerate this file in
        the same commit."""
        content = Guard.write_manifest(repository).read_text()
        assert "cannot be silent" in content
        assert "reviewed" in content


class TestWorktrees:
    def test_a_linked_worktree_is_handled(self, repository, tmp_path) -> None:
        """In a linked worktree `.git` is a file containing a pointer, not a
        directory. Ignoring that installs hooks into a path that does not exist
        and reports success."""
        (repository / "a.txt").write_text("x")
        git(repository, "add", "a.txt")
        git(repository, "commit", "-q", "-m", "initial")

        linked = tmp_path / "linked"
        git(repository, "worktree", "add", "-q", str(linked), "-b", "side")

        assert (linked / ".git").is_file(), "expected a gitdir pointer file"
        Guard.install_hooks(linked)
        assert Guard.verify(linked).ok
