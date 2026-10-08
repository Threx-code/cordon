"""Code from elsewhere, scanned before it is checked out or merged (`core/incoming.py`).

The compromised commit in every test is a lockfile pinning flatmap-stream 0.1.1, the release
behind the 2018 event-stream incident: a known record in the bundled intel, named by version,
with no code of any kind.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.errors import ConfigError
from cordon_scanner.core.guard import INCOMING_HOOKS, SHIM_MARKER, Guard
from cordon_scanner.core.incoming import Incoming
from cordon_scanner.sources.git import GitRepository, GitTreeSource


class Repo:
    """Real git repositories in a temporary directory, and the configuration a check runs on."""

    @staticmethod
    def git(cwd: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-c", "init.defaultBranch=main", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @staticmethod
    def commit(repo: Path, files: dict[str, str], message: str = "change") -> str:
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text)
        Repo.git(repo, "add", "-A")
        Repo.git(repo, "commit", "-q", "-m", message)
        return Repo.git(repo, "rev-parse", "HEAD")

    @staticmethod
    def npm_project(dependency: str, version: str) -> dict[str, str]:
        lock = {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": {dependency: version}},
                f"node_modules/{dependency}": {
                    "version": version,
                    "resolved": f"https://registry.npmjs.org/{dependency}/-/{dependency}-{version}.tgz",
                },
            },
        }
        return {
            "package.json": json.dumps({"name": "app", "dependencies": {dependency: version}}),
            "package-lock.json": json.dumps(lock),
        }

    @staticmethod
    def config() -> Config:
        return Incoming.config(Config.default().with_overrides(use_cache=False))


CLEAN = Repo.npm_project("ms", "2.1.3")
COMPROMISED = Repo.npm_project("flatmap-stream", "0.1.1")


class GitWorld:
    """A home of its own for git, so no developer's configuration or hooks reach a test."""

    @pytest.fixture(autouse=True)
    def _git_identity(self, tmp_path_factory, monkeypatch) -> None:
        home = tmp_path_factory.mktemp("home")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        for key in ("AUTHOR", "COMMITTER"):
            monkeypatch.setenv(f"GIT_{key}_NAME", "Test")
            monkeypatch.setenv(f"GIT_{key}_EMAIL", "test@example.invalid")
        monkeypatch.delenv("CORDON_INCOMING", raising=False)

    @pytest.fixture
    def upstream(self, tmp_path) -> Path:
        repo = tmp_path / "upstream"
        repo.mkdir()
        Repo.git(repo, "init", "-q")
        Repo.commit(repo, {"README.md": "app\n", **CLEAN}, "initial")
        return repo


class TestTheCommitTree(GitWorld):
    def test_a_tree_is_read_from_the_objects_not_the_working_tree(self, upstream) -> None:
        rev = Repo.git(upstream, "rev-parse", "HEAD")
        (upstream / "package-lock.json").write_text("changed on disk, never committed")
        source = GitTreeSource(GitRepository(upstream), rev)
        assert "package-lock.json" in source.selected_paths
        assert (
            GitRepository(upstream).blob_at(rev, "package-lock.json")
            == CLEAN["package-lock.json"].encode()
        )

    def test_links_and_submodules_are_not_read_as_files(self, upstream) -> None:
        (upstream / "link").symlink_to("README.md")
        rev = Repo.commit(upstream, {}, "link")
        assert "link" not in GitRepository(upstream).tree_files(rev)


class TestClone(GitWorld):
    def test_a_clean_repository_is_checked_out(self, upstream, tmp_path) -> None:
        target = tmp_path / "clone"
        check = Incoming.clone(str(upstream), target, Repo.config())
        assert check is not None and check.ok
        assert (target / "package-lock.json").read_text() == CLEAN["package-lock.json"]

    def test_a_compromised_repository_is_never_checked_out(self, upstream, tmp_path) -> None:
        Repo.commit(upstream, COMPROMISED, "compromise")
        target = tmp_path / "clone"
        check = Incoming.clone(str(upstream), target, Repo.config())
        assert check is not None and not check.ok
        assert {f.rule_id for f in check.blocking} >= {"MALWARE.DEPENDENCY.KNOWN.001"}
        assert not target.exists()

    def test_the_repository_cannot_configure_its_own_check(self, upstream, tmp_path) -> None:
        Repo.commit(
            upstream,
            {
                **COMPROMISED,
                "cordon.yaml": "version: 1\nscan:\n  severity_threshold: critical\npolicy:\n  fail_on: null\n",
            },
            "compromise, and try to silence it",
        )
        check = Incoming.clone(str(upstream), tmp_path / "clone", Repo.config())
        assert check is not None and not check.ok

    def test_an_occupied_directory_or_an_option_shaped_url_is_refused(
        self, upstream, tmp_path
    ) -> None:
        occupied = tmp_path / "occupied"
        occupied.mkdir()
        (occupied / "mine.txt").write_text("keep")
        with pytest.raises(ConfigError):
            Incoming.clone(str(upstream), occupied, Repo.config())
        with pytest.raises(ConfigError):
            Incoming.clone("--upload-pack=touch /tmp/x", tmp_path / "x", Repo.config())
        assert (occupied / "mine.txt").read_text() == "keep"

    def test_the_default_directory_is_the_one_git_would_choose(self) -> None:
        assert Incoming.default_directory("https://github.com/Threx-code/cordon.git") == "cordon"
        assert Incoming.default_directory("git@github.com:org/app") == "app"


class TestPull(GitWorld):
    @pytest.fixture
    def checkout(self, upstream, tmp_path) -> Path:
        target = tmp_path / "mine"
        Repo.git(tmp_path, "clone", "-q", str(upstream), str(target))
        return target

    def test_a_compromised_push_is_not_merged(self, upstream, checkout) -> None:
        before = Repo.git(checkout, "rev-parse", "HEAD")
        Repo.commit(upstream, COMPROMISED, "a teammate's compromised push")
        check, outcome = Incoming.pull(checkout, Repo.config())
        assert check is not None and not check.ok and outcome.startswith("not merged")
        assert Repo.git(checkout, "rev-parse", "HEAD") == before
        assert (checkout / "package-lock.json").read_text() == CLEAN["package-lock.json"]

    def test_a_clean_push_is_merged(self, upstream, checkout) -> None:
        pushed = Repo.commit(upstream, {"docs.md": "more\n"}, "docs")
        check, outcome = Incoming.pull(checkout, Repo.config())
        assert check is not None and check.ok and outcome.startswith("merged")
        assert Repo.git(checkout, "rev-parse", "HEAD") == pushed

    def test_what_the_checkout_already_had_is_not_counted_again(self, upstream, tmp_path) -> None:
        Repo.commit(upstream, COMPROMISED, "already compromised")
        mine = tmp_path / "mine"
        Repo.git(tmp_path, "clone", "-q", str(upstream), str(mine))
        Repo.commit(upstream, {"docs.md": "more\n"}, "docs")
        check, outcome = Incoming.pull(mine, Repo.config())
        assert (
            check is not None and check.ok and check.inherited >= 1 and outcome.startswith("merged")
        )

    def test_nothing_new_is_up_to_date(self, checkout) -> None:
        assert Incoming.pull(checkout, Repo.config()) == (None, "already up to date")


class TestTheHooks(GitWorld):
    def test_a_blocked_merge_is_undone_and_uncommitted_work_kept(self, upstream, tmp_path) -> None:
        mine = tmp_path / "mine"
        Repo.git(tmp_path, "clone", "-q", str(upstream), str(mine))
        before = Repo.git(mine, "rev-parse", "HEAD")
        Repo.commit(upstream, COMPROMISED, "compromised")
        (mine / "notes.txt").write_text("mine, not committed")
        Repo.git(mine, "pull", "-q", "--ff-only")
        check = Incoming.after_merge(mine, Repo.config())
        assert check is not None and not check.ok
        assert Repo.git(mine, "rev-parse", "HEAD") == before
        assert (mine / "notes.txt").read_text() == "mine, not committed"

    def test_a_blocked_clone_has_its_files_removed(self, upstream, tmp_path) -> None:
        Repo.commit(upstream, COMPROMISED, "compromised")
        mine = tmp_path / "mine"
        Repo.git(tmp_path, "clone", "-q", str(upstream), str(mine))
        head = Repo.git(mine, "rev-parse", "HEAD")
        check = Incoming.after_checkout(mine, "0" * 40, head, "1", Repo.config())
        assert check is not None and not check.ok
        assert (
            not (mine / "package-lock.json").exists()
            and (mine / ".git" / "CORDON_BLOCKED").is_file()
        )
        assert Repo.git(mine, "show", "HEAD:package-lock.json")  # still readable, deliberately

    def test_a_blocked_branch_switch_goes_back(self, upstream, tmp_path) -> None:
        Repo.git(upstream, "checkout", "-q", "-b", "teammate")
        Repo.commit(upstream, COMPROMISED, "compromised")
        Repo.git(upstream, "checkout", "-q", "main")
        mine = tmp_path / "mine"
        Repo.git(tmp_path, "clone", "-q", str(upstream), str(mine))
        main = Repo.git(mine, "rev-parse", "HEAD")
        Repo.git(mine, "checkout", "-q", "teammate")
        check = Incoming.after_checkout(
            mine, main, Repo.git(mine, "rev-parse", "HEAD"), "1", Repo.config()
        )
        assert check is not None and not check.ok
        assert Repo.git(mine, "rev-parse", "--abbrev-ref", "HEAD") == "main"

    def test_commands_that_already_scanned_do_not_scan_again(self, upstream, monkeypatch) -> None:
        monkeypatch.setenv("CORDON_INCOMING", "1")
        assert Incoming.after_merge(upstream, Repo.config()) is None
        assert Incoming.after_checkout(upstream, "a" * 40, "b" * 40, "1", Repo.config()) is None

    def test_a_file_checkout_is_not_a_switch(self, upstream) -> None:
        assert Incoming.after_checkout(upstream, "a" * 40, "b" * 40, "0", Repo.config()) is None


class TestInstallation(GitWorld):
    def test_the_incoming_shims_pass_gits_arguments_and_read_no_repository_policy(
        self, upstream
    ) -> None:
        Guard.install_hooks(upstream)
        for hook in INCOMING_HOOKS:
            text = (upstream / ".git" / "hooks" / hook).read_text()
            assert SHIM_MARKER in text and f'guard incoming {hook} "$@"' in text
            assert "cordon-policy.yaml" not in text and "CORDON_INCOMING" in text

    def test_global_install_seeds_every_new_repository(self, tmp_path) -> None:
        template, installed = Guard.install_global()
        assert set(installed) >= set(INCOMING_HOOKS)
        assert Repo.git(tmp_path, "config", "--global", "init.templateDir") == str(template)
        fresh = tmp_path / "fresh"
        Repo.git(tmp_path, "init", "-q", str(fresh))
        assert SHIM_MARKER in (fresh / ".git" / "hooks" / "post-merge").read_text()

    def test_global_install_keeps_an_existing_template_and_its_hooks(self, tmp_path) -> None:
        mine = tmp_path / "my-template"
        (mine / "hooks").mkdir(parents=True)
        (mine / "hooks" / "post-merge").write_text("#!/bin/sh\necho mine\n")
        Repo.git(tmp_path, "config", "--global", "init.templateDir", str(mine))
        with pytest.raises(Exception, match="post-merge"):
            Guard.install_global()
        assert (mine / "hooks" / "post-merge").read_text() == "#!/bin/sh\necho mine\n"
        assert SHIM_MARKER in (mine / "hooks" / "post-checkout").read_text()


class TestRemovingABlockedClone:
    def test_a_file_held_open_for_a_moment_is_retried(self, tmp_path, monkeypatch) -> None:
        """Windows: a file another process still holds (WinError 32) fails the delete for a
        moment after git exits. The removal retries rather than crashing the check."""
        import os

        root = tmp_path / "clone"
        (root / ".git" / "objects").mkdir(parents=True)
        held = root / ".git" / "objects" / "pack"
        held.write_bytes(b"x")
        real_unlink = os.unlink
        refusals = {"left": 3}

        def unlink(path, *args, **kwargs):
            # By name: on Linux rmtree deletes relative to a directory handle, so `path` is the
            # file's name alone; on Windows it is the full path.
            if Path(path).name == held.name and refusals["left"]:
                refusals["left"] -= 1
                raise PermissionError(32, "being used by another process", str(path))
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", unlink)
        monkeypatch.setattr("cordon_scanner.core.incoming.time.sleep", lambda _: None)
        Incoming._remove(root, keep_directory=False)
        assert not root.exists()
        assert refusals["left"] == 0
