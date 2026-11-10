"""Hex through Cordon (`sources/install/managers/hex.py`, `cli/commands/install/hex.py`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.hex import HexPlanner
from cordon_scanner.sources.install.plan import InstallRefused

OUTER = "c5eb0cab91f094599f94d55bc63409236a8ec69a21a67814529e8d5f6cc90b3b"
JASON = (
    f'  "jason": {{:hex, :jason, "1.4.4", "{"b9" * 32}", [:mix], '
    '[{:decimal, "~> 1.0 or ~> 2.0", [hex: :decimal, repo: "hexpm", optional: true]}], '
    f'"hexpm", "{OUTER}"}},'
)
PLUG = (
    f'  "plug": {{:hex, :plug, "1.16.1", "{"aa" * 32}", [:mix], '
    '[{:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}], '
    f'"hexpm", "{"bb" * 32}"}},'
)


class HexKit:
    @staticmethod
    def lock(*entries: str) -> str:
        return "%{\n" + "\n".join(entries) + "\n}\n"

    DECLARED = (
        "* jason (Hex package) (mix)\n  locked at 1.4.4 (jason) c5eb0cab\n"
        '  the dependency is not available, run "mix deps.get"\n'
        "* local_lib (../local_lib) (mix)\n"
        '  the dependency is not available, run "mix deps.get"\n'
    )


class TestTheLock:
    def test_each_hex_package_is_held_to_its_outer_checksum(self) -> None:
        (file,) = HexPlanner.files(HexKit.lock(JASON))
        assert (file.name, file.version, file.algorithm) == ("jason", "1.4.4", "sha256")
        assert file.url == "https://repo.hex.pm/tarballs/jason-1.4.4.tar"
        assert file.digest == bytes.fromhex(OUTER)

    def test_a_git_dependency_is_refused(self) -> None:
        git = '  "x": {:git, "https://example.invalid/x.git", "abc", []},'
        with pytest.raises(InstallRefused, match="git"):
            HexPlanner.files(HexKit.lock(git))

    def test_another_repository_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match=r"not hex\.pm"):
            HexPlanner.files(HexKit.lock(JASON.replace('"hexpm", "c5', '"acme", "c5')))

    def test_no_lock_and_an_update_are_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no mix\.lock"):
            HexPlanner.plan(["deps.get"], tmp_path)
        with pytest.raises(InstallRefused, match=r"deps\.update"):
            HexPlanner.plan(["deps.update", "--all"], tmp_path)


class TestWhatIsNotPinned:
    def test_a_declared_dependency_without_a_lock_entry(self) -> None:
        declared = (
            HexKit.DECLARED + "* telemetry (Hex package)\n  the dependency is not available\n"
        )
        assert HexPlanner.unpinned(declared, HexKit.lock(JASON)) == ["telemetry"]

    def test_a_path_dependency_and_an_optional_need_are_the_projects(self) -> None:
        assert HexPlanner.unpinned(HexKit.DECLARED, HexKit.lock(JASON)) == []

    def test_a_package_a_pinned_one_needs(self) -> None:
        assert HexPlanner.unpinned("", HexKit.lock(JASON, PLUG)) == ["mime"]


class TestTheInstall:
    def test_the_scanned_tarballs_go_where_hex_looks(self, tmp_path: Path) -> None:
        (file,) = HexPlanner.files(HexKit.lock(JASON))
        (tmp_path / file.filename).write_bytes(b"scanned")
        HexPlanner.seed([file], tmp_path, tmp_path / "cache")
        assert (tmp_path / "cache" / "jason-1.4.4.tar").read_bytes() == b"scanned"

    def test_what_counts_as_an_install(self) -> None:
        assert HexPlanner.installs(["deps.get"]) and HexPlanner.installs(["deps.update", "x"])
        assert not HexPlanner.installs(["compile"]) and not HexPlanner.installs([])
