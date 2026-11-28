"""SwiftPM through Cordon (`sources/install/managers/swift.py`), on SwiftLint's real Package.resolved and GitHub's real tarball.

`swift_captures/Package.resolved` is the one SwiftLint's repository holds (nine pins, all on GitHub); the tarball is what GitHub serves
for the pinned commit of CollectionConcurrencyKit, which names that commit in its header."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.sources.install.hashes import ArchiveDigest
from cordon_scanner.sources.install.managers.swift import SwiftPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "swift_captures"
RESOLVED = (CAPTURES / "Package.resolved").read_text(encoding="utf-8")
CCK = "b4f23e24b5a1bff301efc5e70871083ca029ff95"


class TestThePins:
    def test_each_dependency_is_the_commit_tarball_held_to_its_commit(self) -> None:
        files = SwiftPlanner.files(RESOLVED)
        assert len(files) == 9
        cck = next(f for f in files if f.name == "JohnSundell/CollectionConcurrencyKit")
        assert (cck.version, cck.algorithm, cck.digest.hex()) == ("0.2.0", "git-commit", CCK)
        assert (
            cck.url
            == f"https://codeload.github.com/JohnSundell/CollectionConcurrencyKit/tar.gz/{CCK}"
        )

    def test_the_tarball_must_name_the_pinned_commit(self) -> None:
        (cck,) = [
            f for f in SwiftPlanner.files(RESOLVED) if f.name.endswith("CollectionConcurrencyKit")
        ]
        data = (CAPTURES / "CollectionConcurrencyKit-b4f23e24.tar.gz").read_bytes()
        assert ArchiveDigest.of(cck.algorithm, data) == cck.digest
        other = next(f for f in SwiftPlanner.files(RESOLVED) if f.name != cck.name)
        assert ArchiveDigest.of(other.algorithm, data) != other.digest

    def test_a_dependency_off_github_is_refused(self) -> None:
        document = json.loads(RESOLVED)
        document["pins"][0]["location"] = "https://example.invalid/x/y.git"
        with pytest.raises(InstallRefused, match="Cordon checks Swift packages on GitHub"):
            SwiftPlanner.files(json.dumps(document))

    def test_a_branch_pin_without_a_commit_is_refused(self) -> None:
        document = json.loads(RESOLVED)
        document["pins"][0]["state"] = {"branch": "main"}
        with pytest.raises(InstallRefused, match="no commit"):
            SwiftPlanner.files(json.dumps(document))

    def test_a_registry_dependency_is_refused(self) -> None:
        document = json.loads(RESOLVED)
        document["pins"][0]["kind"] = "registry"
        with pytest.raises(InstallRefused):
            SwiftPlanner.files(json.dumps(document))

    def test_no_resolved_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no Package\.resolved"):
            SwiftPlanner.plan(["build"], tmp_path)


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["build"], True),
            (["build", "-c", "release"], True),
            (["--package-path", "x", "test"], True),
            (["run", "tool"], True),
            (["package", "resolve"], True),
            (["package", "update"], True),
            (["package", "clean"], False),
            (["--version"], False),
            (["file.swift"], False),
            ([], False),
        ],
    )
    def test_which_commands_resolve_dependencies(self, args: list[str], installs: bool) -> None:
        assert SwiftPlanner.installs(args) is installs

    @pytest.mark.parametrize("sub", ["update", "add", "edit"])
    def test_a_command_that_chooses_versions_is_refused(self, sub: str, tmp_path: Path) -> None:
        (tmp_path / "Package.resolved").write_text(RESOLVED, encoding="utf-8")
        with pytest.raises(InstallRefused, match="chooses dependency versions"):
            SwiftPlanner.plan(["package", sub], tmp_path)

    def test_swiftpm_keeps_to_the_pins_too(self) -> None:
        assert SwiftPlanner.arguments(["build", "-c", "release"]) == [
            "build",
            "--disable-automatic-resolution",
            "-c",
            "release",
        ]
        assert SwiftPlanner.arguments(["package", "resolve"]) == [
            "package",
            "resolve",
            "--disable-automatic-resolution",
        ]
