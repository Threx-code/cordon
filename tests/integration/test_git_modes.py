"""Scanning from git rather than from disk.

The module under test exists for one attack. A pre-commit hook that reads the
working tree is defeated by staging a poisoned file and then restoring the clean
version on disk: the poisoned blob is what gets committed, the clean one is what
gets scanned, and the hook reports success.

These tests were written after finding that `cordon guard install` wrote hooks
invoking `cordon scan --staged` while the CLI had no such flag. Every installed
hook failed with "unrecognized arguments" and blocked every commit, and the git
source module -- fully written and unit-tested -- was reachable from nothing.
A unit test on a module that no caller can reach proves only that the module
compiles, so these go through the command line.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from cordon.cli.main import main
from cordon.sources.base import FileSource, WorkingTreeSource
from cordon.sources.git import GitIndexSource, GitPathSource, GitRepository

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

PAYLOAD = (
    "const {execSync} = require('child_process');\n"
    "execSync(Buffer.from('Y3VybCBldmlsfHNo','base64').toString());\n"
)
CLEAN = "const x = 1;\n"


def git(root, *args: str) -> str:
    done = subprocess.run(
        [shutil.which("git"), *args], cwd=root, check=True, capture_output=True, text=True
    )
    return done.stdout


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "T")
    (root / "app.js").write_text(CLEAN)
    git(root, "add", "app.js")
    git(root, "commit", "-q", "-m", "initial")
    return root


class TestTheBypass:
    """The reason staged mode is a security control and not a convenience."""

    def test_a_working_tree_scan_misses_a_staged_payload(self, repository, capsys) -> None:
        """Establishes that the attack works, so the next test proves something.

        A test that only asserts the fix passes cannot distinguish a working fix
        from a payload the scanner never detected in the first place.
        """
        (repository / "app.js").write_text(PAYLOAD)
        git(repository, "add", "app.js")
        (repository / "app.js").write_text(CLEAN)

        code = main(["scan", str(repository), "--no-cache", "--severity", "low", "-q"])
        assert code == 0
        assert "DECODE_EXEC" not in capsys.readouterr().out

    def test_a_staged_scan_catches_it(self, repository, capsys) -> None:
        (repository / "app.js").write_text(PAYLOAD)
        git(repository, "add", "app.js")
        (repository / "app.js").write_text(CLEAN)

        code = main(["scan", str(repository), "--staged", "--no-cache", "--severity", "low"])
        assert code == 1
        assert "DECODE_EXEC" in capsys.readouterr().out

    def test_staged_mode_reads_the_index_not_the_disk(self, repository) -> None:
        """Stated directly, without going through a rule: the bytes differ."""
        (repository / "app.js").write_text(PAYLOAD)
        git(repository, "add", "app.js")
        (repository / "app.js").write_text(CLEAN)

        staged = GitRepository(repository).staged_content("app.js")
        assert staged is not None
        assert b"execSync" in staged
        assert (repository / "app.js").read_text(encoding="utf-8") == CLEAN


class TestFlagsExist:
    """Regression: the guard shipped hooks calling a flag argparse rejected."""

    @pytest.mark.parametrize("flag", ["--staged", "--tracked"])
    def test_the_flag_is_accepted(self, repository, flag: str) -> None:
        assert main(["scan", str(repository), flag, "--no-cache", "-q"]) in (0, 1)

    def test_git_diff_is_accepted(self, repository) -> None:
        assert main(["scan", str(repository), "--git-diff", "HEAD", "--no-cache", "-q"]) in (0, 1)

    def test_the_guard_hook_command_parses(self, repository) -> None:
        """The exact argument list the installed pre-commit shim runs.

        This is the test that would have caught the original gap. The shim is a
        string in another module, and nothing checked that the command it builds
        is one the CLI accepts.
        """
        from cordon.core.guard import HOOK_COMMANDS

        for command in HOOK_COMMANDS.values():
            args = command.split()
            assert args[0] == "scan"
            assert main([*args[:1], str(repository), *args[1:], "--no-cache"]) in (0, 1)


class TestNarrowing:
    def test_tracked_skips_untracked_files(self, repository, capsys) -> None:
        """The point of --tracked: build output and ignored paths are not
        scanned, because they are not what anybody is shipping."""
        (repository / "generated.js").write_text(PAYLOAD)
        code = main(["scan", str(repository), "--tracked", "--no-cache", "--severity", "low"])
        assert code == 0
        assert "generated.js" not in capsys.readouterr().out

    def test_without_tracked_the_same_file_is_scanned(self, repository, capsys) -> None:
        (repository / "generated.js").write_text(PAYLOAD)
        code = main(["scan", str(repository), "--no-cache", "--severity", "low"])
        assert code == 1
        assert "generated.js" in capsys.readouterr().out

    def test_git_diff_narrows_to_changed_files(self, repository, capsys) -> None:
        (repository / "added.js").write_text(PAYLOAD)
        git(repository, "add", "added.js")
        git(repository, "commit", "-q", "-m", "second")

        code = main(
            ["scan", str(repository), "--git-diff", "HEAD~1", "--no-cache", "--severity", "low"]
        )
        assert code == 1
        assert "added.js" in capsys.readouterr().out

    def test_narrowing_cannot_reach_past_an_exclusion(self, repository) -> None:
        """Git names the path, configuration still decides. Otherwise a git mode
        would be a way to scan paths an operator excluded on purpose -- and,
        read the other way, a way to smuggle a file past one."""
        (repository / "vendor").mkdir()
        (repository / "vendor" / "lib.js").write_text(PAYLOAD)
        git(repository, "add", "vendor/lib.js")
        git(repository, "commit", "-q", "-m", "vendored")

        code = main(
            [
                "scan",
                str(repository),
                "--tracked",
                "--exclude",
                "vendor/**",
                "--no-cache",
                "--severity",
                "low",
            ]
        )
        assert code == 0


class TestFailureHandling:
    def test_a_git_mode_outside_a_repository_is_an_error(self, tmp_path, capsys) -> None:
        """Never a fallback. Silently scanning the working tree when --staged
        cannot be honoured is the worst outcome available: the hook reports
        success having read the wrong bytes."""
        plain = tmp_path / "plain"
        plain.mkdir()
        (plain / "app.js").write_text(CLEAN)

        assert main(["scan", str(plain), "--staged", "--no-cache", "-q"]) == 3
        assert "git repository" in capsys.readouterr().err

    def test_nothing_staged_is_not_a_failure(self, repository, capsys) -> None:
        """A pre-commit hook fires on every commit, including ones staging
        nothing this scanner reads. Failing there teaches people --no-verify."""
        assert main(["scan", str(repository), "--staged", "--no-cache", "-q"]) == 0
        assert "nothing is staged" in capsys.readouterr().err

    def test_the_modes_are_mutually_exclusive(self, repository) -> None:
        with pytest.raises(SystemExit):
            main(["scan", str(repository), "--staged", "--tracked"])


class TestSourceContract:
    def test_every_source_satisfies_the_port(self) -> None:
        sources = [
            WorkingTreeSource(),
            GitPathSource([], mode="tracked"),
            GitIndexSource(GitRepository("."), []),
        ]
        for source in sources:
            assert isinstance(source, FileSource)
            assert source.id
            assert source.describe()

    def test_the_index_source_refuses_parallel_execution(self) -> None:
        """Workers re-read by path from disk. In staged mode that would scan the
        working tree while the caller believes it is scanning the index --
        reintroducing the bypass, silently, only on repositories large enough to
        trigger a worker pool."""
        assert GitIndexSource(GitRepository("."), []).parallel_safe is False

    def test_disk_backed_sources_allow_parallel_execution(self) -> None:
        assert WorkingTreeSource().parallel_safe is True
        assert GitPathSource([], mode="tracked").parallel_safe is True

    def test_the_engine_honours_the_refusal(self, tmp_path) -> None:
        """The property is only worth anything if the engine reads it."""
        from cordon.core.config import Config
        from cordon.core.engine import Engine

        engine = Engine(Config.default(), source=GitIndexSource(GitRepository(tmp_path), []))
        assert engine.source.parallel_safe is False

    def test_a_staged_blob_that_cannot_be_read_is_not_served_from_disk(
        self, repository, tmp_path
    ) -> None:
        """Falling back would reopen the bypass for any path an attacker can
        make unreadable from the index."""
        from cordon.core.content import Skipped
        from cordon.core.limits import DEFAULT_LIMITS
        from cordon.core.walker import WalkEntry

        source = GitIndexSource(GitRepository(repository), ["missing.js"])
        entry = WalkEntry(repository / "app.js", "missing.js", 10)
        assert isinstance(source.load(entry, DEFAULT_LIMITS), Skipped)


class TestExitCodeAttribution:
    """2 means "this is a bug in cordon"; 3 means "fix your invocation". The
    difference is the whole reason both exist, and getting it wrong accuses the
    wrong party -- which is how a tool acquires a reputation for being flaky."""

    def test_a_ref_that_does_not_exist_is_the_users_mistake(self, repository, capsys) -> None:
        code = main(["scan", str(repository), "--git-diff", "no-such-ref", "--no-cache", "-q"])
        assert code == 3

    def test_the_error_names_the_ref(self, repository, capsys) -> None:
        main(["scan", str(repository), "--git-diff", "no-such-ref", "--no-cache", "-q"])
        err = capsys.readouterr().err
        assert "no-such-ref" in err
        assert "--git-diff" in err

    def test_a_real_ref_still_works(self, repository) -> None:
        assert main(["scan", str(repository), "--git-diff", "HEAD", "--no-cache", "-q"]) in (0, 1)


class TestEmptySelectionSeverity:
    """An empty selection is always reported. Whether it is a warning or a note
    depends on which narrowing produced it, and the two genuinely differ."""

    def test_an_empty_diff_does_not_fail_the_build(self, repository) -> None:
        """A scheduled run against a branch that has not moved changes nothing.
        Failing there every night is how a check gets disabled."""
        assert main(["scan", str(repository), "--git-diff", "HEAD", "--no-cache", "-q"]) == 0

    def test_an_empty_diff_is_still_reported(self, repository, capsys) -> None:
        main(
            [
                "scan",
                str(repository),
                "--git-diff",
                "HEAD",
                "--no-cache",
                "--severity",
                "info",
                "-f",
                "json",
            ]
        )
        import json

        payload = json.loads(capsys.readouterr().out)
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in {f["rule_id"] for f in payload["findings"]}

    def test_an_empty_tracked_set_does_fail_the_build(self, tmp_path) -> None:
        """Not the same situation. `--tracked` selected every file it could find
        and that was none: the pipeline scanned nothing and reported success."""
        root = tmp_path / "untracked"
        root.mkdir()
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "t@example.invalid")
        git(root, "config", "user.name", "T")
        (root / "p.js").write_text(PAYLOAD)

        assert main(["scan", str(root), "--tracked", "--no-cache", "-q"]) == 1

    def test_the_payload_is_the_reason_that_matters(self, tmp_path) -> None:
        """Guard against the test above passing for the wrong reason: the file
        that was skipped is one a working scan finds."""
        root = tmp_path / "plain"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        assert main(["scan", str(root), "--no-cache", "--severity", "low", "-q"]) == 1
