"""`clone`, `pull` and the post-checkout / post-merge hook action: what is printed to the person and the
exit code, for a passed, a blocked and an unreadable incoming commit (`cli/commands/incoming.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.incoming import IncomingCommand
from cordon_scanner.engine.incoming import Incoming
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.sources.git import GitRepository


class _Kit:
    @staticmethod
    def check(ok: bool = True, inherited: int = 0, rev: str = "0123456789abcdef") -> Any:
        finding = SimpleNamespace(
            severity=4, rule_id="MAL.TEST.001", location="a.js:3", message="runs a downloaded file"
        )
        return SimpleNamespace(
            ok=ok, rev=rev, inherited=inherited, blocking=() if ok else (finding,)
        )


check = _Kit.check


class TestReport:
    def test_a_passed_commit_is_named_by_twelve_characters_and_its_inherited_count(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        IncomingCommand.report(check(inherited=2), "clone of")
        assert capsys.readouterr().err == (
            "cordon-scanner: clone of 0123456789ab passed (2 already in your checkout)\n"
        )
        IncomingCommand.report(check(), "incoming")
        assert capsys.readouterr().err == "cordon-scanner: incoming 0123456789ab passed\n"

    def test_a_blocked_commit_lists_each_blocking_finding_and_what_was_inherited(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        IncomingCommand.report(check(ok=False, inherited=3), "incoming")
        err = capsys.readouterr().err
        assert "incoming 0123456789ab BLOCKED" in err
        assert "MAL.TEST.001  a.js:3" in err and "runs a downloaded file" in err
        assert "(3 more were already in your checkout and are not counted)" in err


class TestClone:
    @staticmethod
    def _args(**over: Any) -> argparse.Namespace:
        base = {"url": "https://example.invalid/r.git", "directory": None, "branch": None}
        return argparse.Namespace(**{**base, **over})

    def test_a_passed_clone_is_checked_out_into_the_directory_named_after_the_repository(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seen: list[Any] = []
        monkeypatch.setattr(
            Incoming,
            "clone",
            staticmethod(
                lambda url, directory, config, branch=None: (
                    seen.append((directory, branch)) or check()
                )
            ),
        )
        monkeypatch.setattr(Incoming, "default_directory", staticmethod(lambda url: "r"))
        assert IncomingCommand.run_clone(self._args(branch="main")) == int(ExitCode.CLEAN)
        assert seen == [(Path("r"), "main")]
        assert "checked out into r" in capsys.readouterr().out

    def test_a_blocked_clone_is_removed_and_exits_with_findings(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            Incoming, "clone", staticmethod(lambda url, d, config, branch=None: check(ok=False))
        )
        assert IncomingCommand.run_clone(self._args(directory="out")) == int(ExitCode.FINDINGS)
        assert "Nothing was checked out, and out was removed." in capsys.readouterr().err

    def test_an_empty_repository_has_nothing_to_check_and_is_clean(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            Incoming, "clone", staticmethod(lambda url, d, config, branch=None: None)
        )
        assert IncomingCommand.run_clone(self._args(directory="out")) == int(ExitCode.CLEAN)
        assert "cloned an empty repository; there was nothing to check" in capsys.readouterr().err

    def test_the_configuration_is_the_operators_with_the_severity_asked_for(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.foundation.models import Severity

        plain = IncomingCommand._config(argparse.Namespace())
        assert plain.policy.fail_on_severity == Incoming.config().policy.fail_on_severity
        strict = IncomingCommand._config(argparse.Namespace(fail_on="low", config=None))
        assert strict.policy.fail_on_severity == Severity.LOW
        settings = tmp_path / "own.yaml"
        settings.write_text("policy:\n  fail_on_incomplete: true\n", encoding="utf-8")
        own = IncomingCommand._config(argparse.Namespace(config=str(settings), fail_on=None))
        assert own.policy.fail_on_incomplete and not plain.policy.fail_on_incomplete
        assert own.policy.fail_on_severity == plain.policy.fail_on_severity


class TestPull:
    @staticmethod
    def _args(tmp_path: Path, **over: Any) -> argparse.Namespace:
        base = {"path": str(tmp_path), "remote": None, "branch": None, "merge": False}
        return argparse.Namespace(**{**base, **over})

    @staticmethod
    def _pull(monkeypatch: pytest.MonkeyPatch, outcome: tuple[Any, str]) -> None:
        monkeypatch.setattr(
            Incoming, "pull", staticmethod(lambda root, config, remote, branch, merge: outcome)
        )

    @pytest.mark.parametrize(
        ("outcome", "code"),
        [
            ("merged 3 commits", ExitCode.CLEAN),
            ("already up to date", ExitCode.CLEAN),
            ("could not fast-forward", ExitCode.SCANNER_ERROR),
        ],
    )
    def test_the_exit_code_follows_what_git_did_with_a_passing_commit(
        self,
        outcome: str,
        code: ExitCode,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self._pull(monkeypatch, (check(), outcome))
        assert IncomingCommand.run_pull(self._args(tmp_path)) == int(code)
        assert capsys.readouterr().out == outcome + "\n"

    def test_a_blocked_pull_exits_with_findings_whatever_the_outcome_says(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._pull(monkeypatch, (check(ok=False), "merged"))
        assert IncomingCommand.run_pull(self._args(tmp_path)) == int(ExitCode.FINDINGS)

    def test_a_pull_with_nothing_incoming_prints_only_the_outcome(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self._pull(monkeypatch, (None, "already up to date"))
        assert IncomingCommand.run_pull(self._args(tmp_path)) == int(ExitCode.CLEAN)
        captured = capsys.readouterr()
        assert captured.err == "" and captured.out == "already up to date\n"


class TestHook:
    @staticmethod
    def _repo(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, found: bool = True) -> None:
        info = SimpleNamespace(root=tmp_path) if found else None
        monkeypatch.setattr(GitRepository, "discover", staticmethod(lambda path: info))
        monkeypatch.chdir(tmp_path)

    @staticmethod
    def _run(hook: str, *git_args: str) -> int:
        return IncomingCommand.run_hook(argparse.Namespace(hook=hook, git_args=list(git_args)))

    def test_outside_a_repository_and_for_an_unknown_hook_it_is_clean_and_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._repo(monkeypatch, tmp_path, found=False)
        assert self._run("post-merge") == int(ExitCode.CLEAN)
        self._repo(monkeypatch, tmp_path)
        assert self._run("pre-push") == int(ExitCode.CLEAN)
        assert self._run("post-checkout", "a", "b") == int(ExitCode.CLEAN), "needs three arguments"
        assert capsys.readouterr().err == ""

    def test_a_blocked_switch_is_reported_as_undone_and_a_blocked_clone_as_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._repo(monkeypatch, tmp_path)
        monkeypatch.setattr(
            Incoming,
            "after_checkout",
            staticmethod(lambda root, old, new, flag, config: check(ok=False)),
        )
        assert self._run("post-checkout", "abc123", "def456", "1") == int(ExitCode.CLEAN)
        assert "The switch was undone. Nothing in it has been run." in capsys.readouterr().err
        assert self._run("post-checkout", "0000000", "def456", "1") == int(ExitCode.CLEAN)
        assert (
            "Its files were removed from the working tree. Nothing in it has been run."
            in capsys.readouterr().err
        )

    def test_a_blocked_merge_is_reported_as_undone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._repo(monkeypatch, tmp_path)
        monkeypatch.setattr(
            Incoming, "after_merge", staticmethod(lambda root, config: check(ok=False))
        )
        assert self._run("post-merge", "0") == int(ExitCode.CLEAN)
        err = capsys.readouterr().err
        assert (
            "The merge was undone (git reset --merge ORIG_HEAD). Nothing in it has been run." in err
        )

    def test_a_passed_merge_says_so_and_a_hook_with_nothing_to_check_is_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._repo(monkeypatch, tmp_path)
        monkeypatch.setattr(Incoming, "after_merge", staticmethod(lambda root, config: check()))
        assert self._run("post-merge", "0") == int(ExitCode.CLEAN)
        err = capsys.readouterr().err
        assert "passed" in err and "undone" not in err
        monkeypatch.setattr(Incoming, "after_merge", staticmethod(lambda root, config: None))
        assert self._run("post-merge", "0") == int(ExitCode.CLEAN)
        assert capsys.readouterr().err == ""

    def test_a_check_that_fails_warns_and_never_crashes_git(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._repo(monkeypatch, tmp_path)

        def broken(root: Path, config: Any) -> Any:
            raise RuntimeError("object store unreadable")

        monkeypatch.setattr(Incoming, "after_merge", staticmethod(broken))
        assert self._run("post-merge", "0") == int(ExitCode.CLEAN)
        err = capsys.readouterr().err
        assert "could not check the code this post-merge brought in: object store unreadable" in err
        assert "Do not open or build it until it has been checked." in err
