"""Nix flakes through Cordon (`sources/install/managers/nix.py`, `nar_hash.py`), on real locks and the forges' real tarballs.

`nix_captures/` holds three flake.lock files Nix wrote (a GitHub input, a GitLab input, a GitLab and a SourceHut input) and the tarballs
those forges serve for the locked revisions; each lock's `narHash` is the one Nix computed for that tree."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.sources.install.hashes import ArchiveDigest
from cordon_scanner.sources.install.managers.nix import NixPlanner
from cordon_scanner.sources.install.nar_hash import NarHash, NarRefused
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "nix_captures"
GITHUB = (CAPTURES / "github.flake.lock").read_text(encoding="utf-8")
GITLAB = (CAPTURES / "gitlab.flake.lock").read_text(encoding="utf-8")
MIXED = (CAPTURES / "gitlab-sourcehut.flake.lock").read_text(encoding="utf-8")
SYSTEMS = "nix-systems-default-d36eeed142f88b5a636f2e3856a53c61654cf29b.tar.gz"
PAGES = "nix-gitlab-pages-plain-html-87e8c32b.tar.gz"
SCDOC = "nix-sourcehut-scdoc-24be30ef.tar.gz"


class TestTheNarHash:
    @pytest.mark.parametrize(
        ("tarball", "lock", "node"),
        [(SYSTEMS, GITHUB, "systems"), (PAGES, GITLAB, "site"), (SCDOC, MIXED, "scdoc")],
    )
    def test_it_reproduces_the_hash_nix_recorded(self, tarball: str, lock: str, node: str) -> None:
        recorded = json.loads(lock)["nodes"][node]["locked"]
        sri, newest = NarHash.of_tarball((CAPTURES / tarball).read_bytes())
        assert sri == recorded["narHash"]
        assert newest == recorded["lastModified"]

    def test_a_tarball_that_is_not_one_is_refused(self) -> None:
        with pytest.raises(NarRefused):
            NarHash.of_tarball(b"not a tarball")

    def test_the_install_guard_holds_a_file_to_it(self) -> None:
        (file,) = NixPlanner.files(GITHUB)
        assert ArchiveDigest.of(file.algorithm, (CAPTURES / SYSTEMS).read_bytes()) == file.digest
        assert ArchiveDigest.of(file.algorithm, (CAPTURES / PAGES).read_bytes()) != file.digest


class TestTheLock:
    def test_a_github_input_is_the_commit_tarball_held_to_its_nar_hash(self) -> None:
        (file,) = NixPlanner.files(GITHUB)
        assert file.name == "nix-systems/default"
        assert (
            file.url
            == "https://codeload.github.com/nix-systems/default/tar.gz/d36eeed142f88b5a636f2e3856a53c61654cf29b"
        )
        assert file.algorithm == "nar-sha256"

    def test_gitlab_and_sourcehut_inputs_are_read_too(self) -> None:
        urls = {f.url for f in NixPlanner.files(MIXED)}
        assert (
            "https://gitlab.com/api/v4/projects/gitlab-org%2Fcli/repository/archive.tar.gz?sha=9858866c61b13bfdcb0551b407fa558c4c868d8a"
            in urls
        )
        assert (
            "https://git.sr.ht/~sircmpwn/scdoc/archive/24be30ef17d5ca0162f11b35258c8fa2413d556a.tar.gz"
            in urls
        )

    def test_an_input_from_git_is_refused(self) -> None:
        lock = json.loads(GITHUB)
        lock["nodes"]["systems"]["locked"]["type"] = "git"
        with pytest.raises(InstallRefused, match="Cordon checks flake inputs on GitHub"):
            NixPlanner.files(json.dumps(lock))

    def test_an_input_with_no_nar_hash_is_refused(self) -> None:
        lock = json.loads(GITHUB)
        del lock["nodes"]["systems"]["locked"]["narHash"]
        with pytest.raises(InstallRefused, match="cannot read"):
            NixPlanner.files(json.dumps(lock))

    def test_no_lock_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no flake\.lock"):
            NixPlanner.plan(["build"], tmp_path)

    def test_a_project_with_a_lock_is_planned(self, tmp_path: Path) -> None:
        (tmp_path / "flake.lock").write_text(GITHUB, encoding="utf-8")
        assert len(NixPlanner.plan(["build", ".#hello"], tmp_path).files) == 1


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["build"], True),
            (
                ["--extra-experimental-features", "flakes", "build"],
                True,
            ),  # an option's value is no command
            (["run", ".#app"], True),
            (["flake", "check"], True),
            (["--version"], False),
            (["store", "gc"], False),
            ([], False),
        ],
    )
    def test_which_commands_evaluate_a_flake(self, args: list[str], installs: bool) -> None:
        assert NixPlanner.installs(args) is installs

    @pytest.mark.parametrize(
        "args",
        [
            ["flake", "update"],
            ["flake", "lock"],
            ["build", "--update-input", "nixpkgs"],
            ["build", "--recreate-lock-file"],
            ["run", "github:NixOS/nixpkgs#hello"],
            ["run", "nixpkgs#hello"],
            ["shell", "https://example.invalid/x.tar.gz#y"],
        ],
    )
    def test_what_rewrites_the_lock_or_names_a_remote_flake_is_refused(
        self, args: list[str], tmp_path: Path
    ) -> None:
        (tmp_path / "flake.lock").write_text(GITHUB, encoding="utf-8")
        with pytest.raises(InstallRefused):
            NixPlanner.plan(args, tmp_path)

    def test_a_local_flake_and_the_program_arguments_pass(self, tmp_path: Path) -> None:
        (tmp_path / "flake.lock").write_text(GITHUB, encoding="utf-8")
        NixPlanner.plan(["run", ".#app", "--", "github:x/y#z"], tmp_path)

    def test_nix_checks_the_lock_too(self) -> None:
        assert NixPlanner.arguments(["build", ".#x"]) == ["build", "--no-update-lock-file", ".#x"]
