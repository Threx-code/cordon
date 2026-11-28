"""CocoaPods through Cordon (`sources/install/managers/cocoapods.py`), on lines of a real Podfile.lock and the CDN's real podspec.

`cocoapods_captures/` holds four locks cut from the Podfile.lock of artsy/eigen (every line is the real one: an AFNetworking trunk pod, a git
pod with its CHECKOUT OPTIONS commit, a pod from a podspec URL, a `:path` pod), the CDN's podspec of AFNetworking 2.7.0 (whose SHA-1 is the lock's
SPEC CHECKSUMS entry) and GitHub's tarball of the Interstellar commit the lock pins."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.sources.install.hashes import ArchiveDigest
from cordon_scanner.sources.install.managers.cocoapods import CocoaPodsPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "cocoapods_captures"
PODSPEC_URL = "https://cdn.cocoapods.org/Specs/a/7/5/AFNetworking/2.7.0/AFNetworking.podspec.json"
COMMIT = "ca22646f5a8449795fba3d3436a045da0aeb5949"


class Helpers:
    @staticmethod
    def lock(name: str) -> str:
        return (CAPTURES / f"{name}.Podfile.lock").read_text(encoding="utf-8")

    @staticmethod
    def cdn(tamper: bool = False):
        data = (CAPTURES / "AFNetworking-2.7.0.podspec.json").read_bytes()
        return lambda url: (
            (data + b" " if tamper else data)
            if url == PODSPEC_URL
            else pytest.fail(f"unexpected fetch {url}")
        )


class TestTheLock:
    def test_a_trunk_podspec_is_held_to_its_checksum_before_its_source_is_read(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(InstallRefused, match="git tag") as refused:
            CocoaPodsPlanner.files(Helpers.lock("afnetworking"), tmp_path, Helpers.cdn())
        # the podspec was the right one (else the refusal would be about the checksum), and the tag is refused
        assert "not the one" not in str(refused.value)

    def test_a_bare_git_tag_is_refused_naming_the_pod_and_how_to_pin_it(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(InstallRefused) as refused:
            CocoaPodsPlanner.files(Helpers.lock("afnetworking"), tmp_path, Helpers.cdn())
        text = str(refused.value)
        assert "AFNetworking 2.7.0" in text
        assert (
            "Pin :commit (`git ls-remote https://github.com/AFNetworking/AFNetworking.git refs/tags/2.7.0` gives it)"
            in text
        )

    def test_a_podspec_that_is_not_the_one_the_lock_pins_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(
            InstallRefused, match=r"not the one Podfile\.lock's SPEC CHECKSUMS pins"
        ):
            CocoaPodsPlanner.files(Helpers.lock("afnetworking"), tmp_path, Helpers.cdn(tamper=True))

    def test_a_git_pod_is_held_to_the_commit_of_its_checkout_options(self, tmp_path: Path) -> None:
        plan = CocoaPodsPlanner.files(Helpers.lock("interstellar"), tmp_path, Helpers.cdn())
        (file,) = plan.files
        assert (file.name, file.algorithm, file.digest.hex()) == (
            "Interstellar",
            "git-commit",
            COMMIT,
        )
        assert file.url == f"https://codeload.github.com/artsy/Interstellar/tar.gz/{COMMIT}"
        data = (CAPTURES / "Interstellar-ca22646f.tar.gz").read_bytes()
        assert ArchiveDigest.of(file.algorithm, data) == file.digest

    def test_a_pod_from_a_podspec_url_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(
            InstallRefused, match=r"podspec at https://raw\.githubusercontent\.com/braze-inc"
        ):
            CocoaPodsPlanner.files(Helpers.lock("braze"), tmp_path, Helpers.cdn())

    def test_a_path_pod_inside_the_project_is_its_own_code_and_outside_it_is_refused(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "build" / "rndeps-facades" / "boost").mkdir(parents=True)
        plan = CocoaPodsPlanner.files(Helpers.lock("boost"), tmp_path, Helpers.cdn())
        assert plan.local == [(tmp_path / "build" / "rndeps-facades" / "boost").resolve()]
        outside = Helpers.lock("boost").replace(
            "build/rndeps-facades/boost", "../node_modules/boost"
        )
        with pytest.raises(InstallRefused, match="outside this project"):
            CocoaPodsPlanner.files(outside, tmp_path, Helpers.cdn())

    def test_no_lock_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no Podfile\.lock"):
            CocoaPodsPlanner.plan(["install"], tmp_path, Helpers.cdn())


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["install"], True),
            (["--verbose", "install"], True),
            (["update"], True),
            (["repo", "update"], False),
            (["--version"], False),
            ([], False),
        ],
    )
    def test_which_commands_download_pods(self, args: list[str], installs: bool) -> None:
        assert CocoaPodsPlanner.installs(args) is installs

    def test_pod_update_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "Podfile.lock").write_text(Helpers.lock("interstellar"), encoding="utf-8")
        with pytest.raises(InstallRefused, match="chooses pod versions"):
            CocoaPodsPlanner.plan(["update"], tmp_path, Helpers.cdn())

    def test_cocoapods_keeps_to_the_lock_too(self) -> None:
        assert CocoaPodsPlanner.arguments(["install", "--verbose"]) == [
            "install",
            "--deployment",
            "--verbose",
        ]
