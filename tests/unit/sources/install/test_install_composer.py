"""Composer through Cordon (`sources/install/composer.py`, `cli/commands/install/composer.py`)."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.sources.install.composer import ComposerPlanner
from cordon_scanner.sources.install.hashes import CommitArchive
from cordon_scanner.sources.install.plan import InstallRefused

COMMIT = "f4393b648b78a5408747de94fca38beb5f7e9ef8"


class ComposerKit:
    URL = f"https://api.github.com/repos/Seldaek/monolog/zipball/{COMMIT}"
    ENTRY: ClassVar[dict[str, Any]] = {
        "name": "monolog/monolog",
        "version": "3.7.0",
        "dist": {"type": "zip", "url": URL, "reference": COMMIT, "shasum": ""},
    }

    @staticmethod
    def archive(commit: str = COMMIT, root: str | None = None) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr(f"{root or 'Seldaek-monolog-' + commit[:7]}/composer.json", "{}")
            zf.comment = commit.encode()
        return buffer.getvalue()

    @staticmethod
    def done(code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, "", stderr)


class TestTheLock:
    def test_a_github_dist_is_fetched_from_codeload_by_its_commit(self) -> None:
        file = ComposerPlanner.package_file(ComposerKit.ENTRY)
        assert file.url == f"https://codeload.github.com/Seldaek/monolog/legacy.zip/{COMMIT}"
        assert (file.algorithm, file.digest) == ("commit", bytes.fromhex(COMMIT))

    def test_a_published_shasum_is_held_to(self) -> None:
        entry = {**ComposerKit.ENTRY, "dist": {**ComposerKit.ENTRY["dist"], "shasum": "ab" * 20}}
        file = ComposerPlanner.package_file(entry)
        assert (file.algorithm, file.url) == ("sha1", ComposerKit.URL)

    def test_a_dist_with_nothing_to_hold_it_to_is_refused(self) -> None:
        entry = {
            **ComposerKit.ENTRY,
            "dist": {"type": "zip", "url": "https://dl.example.invalid/x.zip", "reference": COMMIT},
        }
        with pytest.raises(InstallRefused, match="no hash to hold it to"):
            ComposerPlanner.package_file(entry)

    def test_a_source_only_package_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="source only"):
            ComposerPlanner.package_file({"name": "a/b", "version": "1.0"})

    def test_dev_packages_follow_no_dev(self) -> None:
        dev = {**ComposerKit.ENTRY, "name": "psr/log"}
        lock = {"packages": [ComposerKit.ENTRY], "packages-dev": [dev]}
        assert [f.name for f in ComposerPlanner.files(lock)] == ["monolog/monolog", "psr/log"]
        assert [f.name for f in ComposerPlanner.files(lock, dev=False)] == ["monolog/monolog"]


class TestTheCommitArchive:
    def test_githubs_archive_of_the_commit_passes(self) -> None:
        ComposerPlanner.package_file(ComposerKit.ENTRY).verify(ComposerKit.archive())

    def test_an_archive_of_another_commit_is_refused(self) -> None:
        other = "0" * 40
        with pytest.raises(InstallRefused, match="does not match"):
            ComposerPlanner.package_file(ComposerKit.ENTRY).verify(ComposerKit.archive(other))

    def test_a_folder_that_does_not_name_the_commit_is_refused(self) -> None:
        with pytest.raises(ValueError, match="folder"):
            CommitArchive.of_zip(ComposerKit.archive(root="evil-0000000"))

    def test_bytes_that_are_not_an_archive_are_refused(self) -> None:
        with pytest.raises(InstallRefused):
            ComposerPlanner.package_file(ComposerKit.ENTRY).verify(b"not a zip")


class TestTheInstall:
    def test_the_scanned_files_seed_composers_cache_under_its_own_key(self, tmp_path: Path) -> None:
        file = ComposerPlanner.package_file(ComposerKit.ENTRY)
        (tmp_path / file.filename).write_bytes(b"scanned")
        ComposerPlanner.seed({"packages": [ComposerKit.ENTRY]}, tmp_path, tmp_path / "c", dev=True)
        key = hashlib.sha1(ComposerKit.URL.encode(), usedforsecurity=False).hexdigest()
        cached = tmp_path / "c" / "files" / "monolog" / "monolog" / f"{key}.zip"
        assert cached.read_bytes() == b"scanned"

    def test_install_runs_offline_and_a_resolve_keeps_only_install_options(self, tmp_path) -> None:
        env = ComposerPlanner.offline_env(tmp_path)
        assert env["COMPOSER_DISABLE_NETWORK"] == "1" and env["COMPOSER_CACHE_DIR"] == str(tmp_path)
        assert ComposerPlanner.install_command("composer", ["require", "a/b", "--no-dev", "-W"]) == [
            "composer", "install", "--no-dev",
        ]  # fmt: skip
        assert ComposerPlanner.install_command("composer", ["install", "-o"]) == [
            "composer",
            "install",
            "-o",
        ]

    def test_a_failed_resolve_puts_the_project_back(self, tmp_path: Path) -> None:
        (tmp_path / "composer.json").write_text('{"name": "demo/app"}', encoding="utf-8")
        seen: list[list[str]] = []

        def runner(
            argv: list[str], cwd: Path, env: dict[str, str]
        ) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            (tmp_path / "composer.json").write_text("changed", encoding="utf-8")
            (tmp_path / "composer.lock").write_text(json.dumps({}), encoding="utf-8")
            return ComposerKit.done(2, "Could not find package cordon/none")

        with pytest.raises(InstallRefused, match="cordon/none"):
            ComposerPlanner.project(
                ["require", "cordon/none"], runner, "composer", tmp_path, tmp_path / "c"
            )
        assert seen[0][-4:] == ["--no-install", "--no-scripts", "--no-plugins", "-n"]
        assert (tmp_path / "composer.json").read_text(encoding="utf-8") == '{"name": "demo/app"}'
        assert not (tmp_path / "composer.lock").exists()

    def test_what_counts_as_an_install(self) -> None:
        assert ComposerPlanner.installs(["require", "a/b"]) and ComposerPlanner.installs(
            ["install"]
        )
        assert not ComposerPlanner.installs(["show"]) and not ComposerPlanner.installs(
            ["update", "--dry-run"]
        )
