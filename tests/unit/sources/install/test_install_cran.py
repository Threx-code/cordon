"""R through Cordon (`sources/install/managers/cran.py`), on a real renv.lock and CRAN's real R6 record and tarball.

`cran_captures/renv.lock` was written by renv 1.3.1 in `rocker/r-ver:4.4.1` (digest in `CAPTURES.md`, run with no network): R6 2.5.1 installed from CRAN's
tarball, then `renv::snapshot(type = "all")`: 17 packages, each `Source: Repository`, `Repository: CRAN`. crandb's record of R6 (with the MD5 CRAN
states for each release) and the 2.5.1 tarball are CRAN's own; the tarball's MD5 is the stated one. `bioconductor.lock` is a real renv.lock from
renv's own tests, with Bioconductor and local packages."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cordon_scanner.intel.registries.archive_sources.upstream import CranArchive
from cordon_scanner.sources.install.hashes import ArchiveDigest
from cordon_scanner.sources.install.managers.cran import CranPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "cran_captures"
RECORD = json.loads((CAPTURES / "crandb-R6-all.json").read_text(encoding="utf-8"))
REAL = json.loads((CAPTURES / "renv.lock").read_text(encoding="utf-8"))
R6 = REAL["Packages"]["R6"]


def locate(name: str, version: str):
    """What CRAN's source says of a release, from the real crandb record."""
    assert name == "R6"
    return CranArchive().locate(
        name,
        version,
        {"version": RECORD["versions"][version], "latest": RECORD["versions"][RECORD["latest"]]},
    )


def lock(*entries: dict[str, object]) -> str:
    return json.dumps({"R": {"Version": "4.4.1"}, "Packages": {e["Package"]: e for e in entries}})


class TestTheLock:
    def test_a_cran_package_is_held_to_the_md5_cran_states(self) -> None:
        (file,) = CranPlanner.files(lock(R6), locate)
        assert (file.name, file.version, file.algorithm) == ("R6", "2.5.1", "md5")
        assert file.url == "https://cran.r-project.org/src/contrib/Archive/R6/R6_2.5.1.tar.gz"
        assert file.digest.hex() == RECORD["versions"]["2.5.1"]["MD5sum"]

    def test_the_real_tarball_matches_and_a_changed_one_does_not(self) -> None:
        (file,) = CranPlanner.files(lock(R6), locate)
        data = (CAPTURES / "cran-R6_2.5.1.tar.gz").read_bytes()
        assert hashlib.md5(data, usedforsecurity=False).digest() == file.digest
        assert ArchiveDigest.of(file.algorithm, data) == file.digest
        assert ArchiveDigest.of(file.algorithm, data + b"x") != file.digest

    def test_a_github_package_is_held_to_its_commit(self) -> None:
        entry = {"Package": "pkg", "Version": "1.0", "Source": "GitHub", "RemoteType": "github", "RemoteHost": "api.github.com",
                 "RemoteUsername": "owner", "RemoteRepo": "pkg", "RemoteSha": "a" * 40}  # fmt: skip
        (file,) = CranPlanner.files(lock(entry), locate)
        assert (file.algorithm, file.digest.hex(), file.url) == (
            "git-commit",
            "a" * 40,
            f"https://codeload.github.com/owner/pkg/tar.gz/{'a' * 40}",
        )

    def test_every_package_of_the_real_lock_is_read_as_a_cran_package(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.base import Located

        def any_release(name: str, version: str) -> Located:
            return Located(
                f"https://cran.r-project.org/src/contrib/{name}_{version}.tar.gz",
                f"{name}_{version}.tar.gz",
                (("md5", "0" * 32),),
            )

        files = CranPlanner.files(json.dumps(REAL), any_release)
        assert len(files) == len(REAL["Packages"]) == 17
        assert {f.algorithm for f in files} == {"md5"}

    def test_the_real_renv_lock_of_a_bioconductor_project_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="Cordon checks R packages from CRAN"):
            CranPlanner.files((CAPTURES / "bioconductor.lock").read_text(encoding="utf-8"), locate)

    def test_a_package_with_no_md5_is_refused(self) -> None:
        from cordon_scanner.intel.registries.registry_request import RegistryError

        def none(name: str, version: str):
            raise RegistryError("cran publishes no archive")

        with pytest.raises(InstallRefused, match="no archive"):
            CranPlanner.files(lock(R6), none)

    def test_no_lock_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no renv\.lock"):
            CranPlanner.plan(["-e", "renv::restore()"], tmp_path, locate)

    def test_the_note_says_how_it_was_verified(self) -> None:
        assert "MD5 alone" in CranPlanner.NOTE and "no size" in CranPlanner.NOTE


class TestTheCommandLine:
    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["-e", "renv::restore()"], True),
            (["-e", "install.packages('R6')"], True),
            (["-e", "pak::pkg_install('R6')"], True),
            (["-e", "library(R6)"], False),
            (["script.R"], False),
            ([], False),
        ],
    )
    def test_which_command_lines_install(self, args: list[str], installs: bool) -> None:
        assert CranPlanner.installs(args) is installs

    @pytest.mark.parametrize(
        "code",
        [
            "install.packages('R6')",
            "renv::install('R6')",
            "remotes::install_github('a/b')",
            "BiocManager::install('x')",
        ],
    )
    def test_what_chooses_versions_is_refused(self, code: str, tmp_path: Path) -> None:
        (tmp_path / "renv.lock").write_text(lock(R6), encoding="utf-8")
        with pytest.raises(InstallRefused, match="chooses package versions"):
            CranPlanner.plan(["-e", code], tmp_path, locate)
