"""Julia through Cordon (`sources/install/managers/julia.py`, `cli/commands/install/locked/julia.py`), on a real manifest.

`julia_captures/` holds the Manifest.toml and Project.toml of SciML/LinearSolve.jl (296 packages, 248 with a tree hash, the rest standard
libraries) and the Pkg server's tarball of JSON 1.13.4 (its tree hash is the one General's Versions.toml records for that release)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cordon_scanner.sources.install.hashes import ArchiveDigest
from cordon_scanner.sources.install.managers.julia import JuliaPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "julia_captures"
JSON_TREE = "06d90f699285d055e34f0b014636a75a17ff2252"


class JuliaKit:
    @staticmethod
    def project(tmp_path: Path, extra_dep: str = "") -> Path:
        shutil.copy(CAPTURES / "Manifest.toml", tmp_path / "Manifest.toml")
        project = (CAPTURES / "Project.toml").read_text(encoding="utf-8")
        if extra_dep:
            project = project.replace("[deps]\n", f"[deps]\n{extra_dep}\n", 1)
        (tmp_path / "Project.toml").write_text(project, encoding="utf-8")
        return tmp_path


class TestTheManifest:
    def test_every_package_with_a_tree_hash_is_held_to_it(self, tmp_path: Path) -> None:
        plan = JuliaPlanner.plan(["-e", "using Pkg; Pkg.instantiate()"], JuliaKit.project(tmp_path))
        assert plan.ecosystem == "julia"
        assert len(plan.files) == 248
        adtypes = next(f for f in plan.files if f.name == "ADTypes")
        assert adtypes.algorithm == "git-tree-sha1"
        assert adtypes.digest.hex() == "629de23e1c16911b439dabd2303c08af9575b226"
        assert (
            adtypes.url
            == "https://pkg.julialang.org/package/47edcb42-4c32-4615-8424-f2b9edc5f35b/629de23e1c16911b439dabd2303c08af9575b226"
        )

    def test_the_tree_hash_is_recomputed_over_the_files_of_the_archive(self) -> None:
        data = (CAPTURES / "JSON-1.13.4.tar.gz").read_bytes()
        assert ArchiveDigest.of("git-tree-sha1", data).hex() == JSON_TREE

    def test_a_project_dependency_the_manifest_does_not_pin_is_refused(
        self, tmp_path: Path
    ) -> None:
        project = JuliaKit.project(tmp_path, 'Unpinned = "12345678-1234-1234-1234-123456789abc"')
        with pytest.raises(InstallRefused, match="does not pin Unpinned"):
            JuliaPlanner.plan(["-e", "Pkg.instantiate()"], project)

    def test_a_package_from_a_git_url_is_refused(self) -> None:
        entry = {
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "repo-url": "https://example.invalid/x.git",
            "git-tree-sha1": "a" * 40,
        }
        with pytest.raises(InstallRefused, match="git repository"):
            JuliaPlanner.files([("X", entry)])

    def test_a_local_path_package_is_the_projects_own_code(self, tmp_path: Path) -> None:
        (tmp_path / "Own").mkdir()
        assert JuliaPlanner.files([("Own", {"path": "Own", "uuid": "x"})]) == []
        assert JuliaPlanner.paths(
            [("Own", {"path": "Own"}), ("Out", {"path": "../x"})], tmp_path
        ) == [(tmp_path / "Own").resolve()]

    def test_the_first_manifest_format_is_read_too(self) -> None:
        entries = JuliaPlanner.entries(
            '[[JSON]]\nuuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"\nversion = "0.21.4"\ngit-tree-sha1 = "'
            + "b" * 40
            + '"\n'
        )
        assert [name for name, _ in entries] == ["JSON"]

    def test_no_manifest_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no Manifest\.toml"):
            JuliaPlanner.plan(["-e", "Pkg.instantiate()"], tmp_path)


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["-e", "using Pkg; Pkg.instantiate()"], True),
            (["--project=.", "-e", "import Pkg; Pkg.build()"], True),
            (["--project", "-e", 'Pkg.add("JSON")'], True),
            (["-e", "using Pkg; Pkg.test()"], True),
            (["script.jl"], False),
            (["--version"], False),
            ([], False),
        ],
    )
    def test_which_command_lines_install(self, args: list[str], installs: bool) -> None:
        assert JuliaPlanner.installs(args) is installs

    @pytest.mark.parametrize("verb", ["add", "update", "develop", "resolve", "rm"])
    def test_a_command_that_chooses_versions_is_refused(self, verb: str, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="chooses versions"):
            JuliaPlanner.plan(["-e", f"using Pkg; Pkg.{verb}()"], JuliaKit.project(tmp_path))
