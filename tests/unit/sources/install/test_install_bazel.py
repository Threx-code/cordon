"""Bazel through Cordon (`sources/install/managers/bazel.py`, `cli/commands/install/bazel.py`), on real registry files.

`bazel_captures/` holds the bytes bcr.bazel.build serves for two modules (each file's sha256 is the one in the real MODULE.bazel.lock of
the bazelbuild/bazel repository) and a lock cut from that real lock: those four registry entries and one real module extension's
generated repositories (`async_profiler_repos`, three `http_archive` and one `http_file`, each with its integrity)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.bazel import BazelPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "bazel_captures"
LOCK = (CAPTURES / "MODULE.bazel.lock").read_text(encoding="utf-8")
REGISTRY = "https://bcr.bazel.build/modules"


class BazelKit:
    @staticmethod
    def registry(tamper: str = "") -> dict[str, bytes]:
        served: dict[str, bytes] = {}
        for name, version in (("bazel_skylib", "1.9.0"), ("abseil-cpp", "20250814.1")):
            for kind in ("MODULE.bazel", "source.json"):
                served[f"{REGISTRY}/{name}/{version}/{kind}"] = (
                    CAPTURES / f"{name}-{version}-{kind}"
                ).read_bytes()
        if tamper:
            served[tamper] = served[tamper] + b" "
        return served

    @classmethod
    def fetch(cls, tamper: str = ""):
        served = cls.registry(tamper)
        return lambda url: served[url]


class TestTheLock:
    def test_every_registry_file_and_download_the_lock_names_is_held_to_a_pin(self) -> None:
        files = BazelPlanner.files(LOCK, BazelKit.fetch())
        by_kind = {
            "module files": [f for f in files if f.url.endswith("/MODULE.bazel")],
            "archives": [f for f in files if f.url.endswith((".tar.gz", ".tar", ".zip"))],
            "generated": [f for f in files if "async_profiler" in f.name],
        }
        assert len(by_kind["module files"]) == 2
        assert len(files) == 2 + 2 + 4
        assert {f.algorithm for f in files} == {"sha256"}
        assert len(by_kind["generated"]) == 4

    def test_a_module_file_is_held_to_the_sha256_of_the_lock(self) -> None:
        files = BazelPlanner.files(LOCK, BazelKit.fetch())
        skylib = next(f for f in files if f.url == f"{REGISTRY}/bazel_skylib/1.9.0/MODULE.bazel")
        assert skylib.digest.hex() == json.loads(LOCK)["registryFileHashes"][skylib.url]

    def test_an_archive_is_held_to_the_integrity_its_source_json_states(self) -> None:
        files = BazelPlanner.files(LOCK, BazelKit.fetch())
        archive = next(f for f in files if f.url.endswith("bazel-skylib-1.9.0.tar.gz"))
        assert archive.digest == base64.b64decode("O1tJAGGB9fj/Ym743c6qlem7itKU97XXsR6p992vjFk=")
        assert archive.algorithm == "sha256"

    def test_a_source_json_that_is_not_the_one_the_lock_pins_is_refused(self) -> None:
        url = f"{REGISTRY}/bazel_skylib/1.9.0/source.json"
        with pytest.raises(InstallRefused, match=r"not the one MODULE\.bazel\.lock pins"):
            BazelPlanner.files(LOCK, BazelKit.fetch(tamper=url))

    def test_a_module_taken_from_git_is_refused(self) -> None:
        url = f"{REGISTRY}/bazel_skylib/1.9.0/source.json"
        git = json.dumps(
            {
                "type": "git_repository",
                "remote": "https://example.invalid/x.git",
                "commit": "a" * 40,
            }
        ).encode()
        served = BazelKit.registry()
        served[url] = git
        pinned = json.loads(LOCK)
        pinned["registryFileHashes"][url] = hashlib.sha256(git).hexdigest()
        with pytest.raises(InstallRefused, match="git_repository"):
            BazelPlanner.files(json.dumps(pinned), lambda u: served[u])

    def test_a_repository_fetched_from_git_is_refused(self) -> None:
        lock = json.loads(LOCK)
        usage = next(iter(next(iter(lock["moduleExtensions"].values())).values()))
        usage["generatedRepoSpecs"]["tool"] = {
            "repoRuleId": "@@bazel_tools//tools/build_defs/repo:git.bzl%git_repository",
            "attributes": {"remote": "https://example.invalid/x.git", "commit": "a" * 40},
        }
        with pytest.raises(InstallRefused, match="fetched from git"):
            BazelPlanner.files(json.dumps(lock), BazelKit.fetch())

    def test_a_download_with_no_integrity_is_refused(self) -> None:
        lock = json.loads(LOCK)
        usage = next(iter(next(iter(lock["moduleExtensions"].values())).values()))
        del usage["generatedRepoSpecs"]["async_profiler"]["attributes"]["integrity"]
        with pytest.raises(InstallRefused, match="no integrity or sha256"):
            BazelPlanner.files(json.dumps(lock), BazelKit.fetch())

    def test_no_lock_and_no_module_file_are_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no MODULE\.bazel here"):
            BazelPlanner.plan(tmp_path, BazelKit.fetch())
        (tmp_path / "MODULE.bazel").write_text('module(name = "x")\n', encoding="utf-8")
        with pytest.raises(InstallRefused, match=r"no MODULE\.bazel\.lock"):
            BazelPlanner.plan(tmp_path, BazelKit.fetch())


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["build", "//..."], True),
            (["--output_base=/tmp/x", "test", "//..."], True),
            (["run", "//app", "--", "--flag"], True),
            (["fetch", "--all"], True),
            (["info"], False),
            (["help", "build"], False),
            (["clean"], False),
            ([], False),
        ],
    )
    def test_which_commands_evaluate_modules(self, args: list[str], installs: bool) -> None:
        assert BazelPlanner.installs(args) is installs

    def test_bazel_checks_the_lock_too(self) -> None:
        assert BazelPlanner.arguments(["build", "//..."]) == [
            "build",
            "//...",
            "--lockfile_mode=error",
        ]
        assert BazelPlanner.arguments(["run", "//app", "--", "-x"]) == [
            "run",
            "//app",
            "--lockfile_mode=error",
            "--",
            "-x",
        ]
