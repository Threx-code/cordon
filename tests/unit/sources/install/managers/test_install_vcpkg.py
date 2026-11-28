"""vcpkg through Cordon: the ports tree at the baseline commit, and each source archive held to the SHA-512 its portfile states.

`vcpkg_captures/ports/` holds the real files of eight ports of microsoft/vcpkg (`vcpkg_captures/CAPTURES.md`). The tests build a git repository
from them, so the ports are read out of a real commit through `GitRepository`, as they are from a person's clone. The vcpkg tool itself was
not run: it downloads CMake first, which was not approved; the planner reads the same files the tool does."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.vcpkg.planner import VcpkgPlanner
from cordon_scanner.sources.install.managers.vcpkg.portfile import Portfile
from cordon_scanner.sources.install.managers.vcpkg.ports import VcpkgPorts
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "managers" / "vcpkg_captures"
ZLIB_SHA512 = "67f3ce120210a69aa05cece6f76d5f45b50d947c095169f0d699732d0182d7d04aec1af56a3fc6bbcc2af91a57e099cd73980b17f7d96ad90aeabbeaafbf1cbc"
APNG_SHA512 = "a27ed2769b3c8d1703267b807663aa8e543b62355237e223d7731662034dd126951b88117c1038dc976750cf515d7e0e26e4a9278bf951f96ec4ed8f74105db7"


class Repository:
    """A git repository of the captured ports, committed once: the baseline."""

    @staticmethod
    def make(folder: Path) -> tuple[Path, str]:
        clone = folder / "vcpkg"
        shutil.copytree(CAPTURES / "ports", clone / "ports")
        env = {
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
            "HOME": str(folder), "PATH": "/usr/bin:/bin:/usr/local/bin",
        }  # fmt: skip
        for command in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "baseline"]):
            subprocess.run(["git", *command], cwd=clone, env=env, check=True, capture_output=True)
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=clone,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return clone, commit

    @staticmethod
    def project(folder: Path, commit: str, **manifest: object) -> Path:
        project = folder / "project"
        project.mkdir()
        document = {"name": "demo", "version": "1.0.0", "builtin-baseline": commit, **manifest}
        (project / "vcpkg.json").write_text(json.dumps(document), encoding="utf-8")
        return project

    @staticmethod
    def plan(folder: Path, args: list[str], **manifest: object):
        clone, commit = Repository.make(folder)
        project = Repository.project(folder, commit, **manifest)
        return VcpkgPlanner.plan(args, project, lambda baseline: VcpkgPorts(clone, baseline))


class TestWhatThePortfilesDownload:
    def text(self, port: str) -> str:
        return (CAPTURES / "ports" / port / "portfile.cmake").read_text(encoding="utf-8")

    def test_vcpkg_from_github_reads_to_the_archive_url_and_its_sha512(self) -> None:
        (source,) = Portfile.sources(self.text("zlib"), "zlib", "1.4")
        assert source.url == "https://github.com/madler/zlib/archive/v1.4.tar.gz"
        assert source.sha512.hex() == ZLIB_SHA512
        assert source.filename == "madler-zlib-v1.4.tar.gz"

    def test_a_distfile_under_a_feature_is_read_with_its_set_variables_expanded(self) -> None:
        sources = Portfile.sources(self.text("libpng"), "libpng", "1.6.59")
        apng = next(s for s in sources if s.sha512.hex() == APNG_SHA512)
        assert apng.url == (
            "https://downloads.sourceforge.net/project/libpng-apng/libpng16/1.6.59/libpng-1.6.59-apng.patch.gz"
        )
        assert apng.filename == "libpng-1.6.59-apng.patch.gz"

    def test_the_first_https_url_is_the_one_fetched_when_a_distfile_lists_http_first(self) -> None:
        (source,) = Portfile.sources(self.text("acl"), "acl", "2.3.2")
        assert source.url.startswith("https://www.mirrorservice.org/")

    def test_a_helper_that_fetches_another_way_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="vcpkg_from_gitlab"):
            Portfile.sources(self.text("cmocka"), "cmocka", "1.1.7")
        with pytest.raises(InstallRefused, match="vcpkg_from_git"):
            Portfile.sources(self.text("aom"), "aom", "3.13.1")

    def test_a_variable_the_portfile_does_not_set_is_refused(self) -> None:
        text = self.text("zlib").replace("v${VERSION}", "${SOMETHING_ELSE}")
        with pytest.raises(InstallRefused, match="SOMETHING_ELSE"):
            Portfile.sources(text, "zlib", "1.4")

    def test_a_download_without_a_sha512_is_refused(self) -> None:
        text = self.text("zlib").replace(ZLIB_SHA512, "0" * 10)
        with pytest.raises(InstallRefused, match="no SHA512"):
            Portfile.sources(text, "zlib", "1.4")


class TestThePlan:
    def test_a_manifest_is_followed_through_its_dependencies_and_default_features(
        self, tmp_path: Path
    ) -> None:
        plan = Repository.plan(tmp_path, ["install"], dependencies=["libpng"])
        names = sorted({f.name for f in plan.files})
        assert names == ["libpng", "zlib"]
        zlib = next(f for f in plan.files if f.name == "zlib")
        assert (zlib.algorithm, zlib.digest.hex()) == ("sha512", ZLIB_SHA512)
        assert zlib.required_by == ("libpng",)
        assert zlib.url == "https://github.com/madler/zlib/archive/v1.4.tar.gz"

    def test_the_download_of_a_feature_is_in_the_plan_only_when_the_feature_is_asked_for(
        self, tmp_path: Path
    ) -> None:
        # libpng's `apng` feature adds one distfile; it is not a default feature, so it is read (the portfile
        # is read wherever a call sits) and held to its hash either way: the plan never holds fewer files than a build downloads.
        plan = Repository.plan(
            tmp_path, ["install"], dependencies=[{"name": "libpng", "features": ["apng"]}]
        )
        assert APNG_SHA512 in {f.digest.hex() for f in plan.files}

    def test_the_features_of_a_dependency_not_asked_for_add_no_ports(self, tmp_path: Path) -> None:
        plan = Repository.plan(
            tmp_path, ["install"], dependencies=[{"name": "libpng", "default-features": False}]
        )
        assert {f.name for f in plan.files} == {"libpng", "zlib"}

    def test_a_version_constraint_the_baseline_does_not_meet_is_refused(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(InstallRefused, match=r"asks for 1\.5 or later"):
            Repository.plan(
                tmp_path, ["install"], dependencies=[{"name": "zlib", "version>=": "1.5"}]
            )

    def test_a_port_the_baseline_does_not_hold_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="no such port"):
            Repository.plan(tmp_path, ["install"], dependencies=["not-a-port"])

    def test_a_port_with_a_source_read_another_way_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="vcpkg_from_gitlab"):
            Repository.plan(tmp_path, ["install"], dependencies=["cmocka"])


class TestWhatIsRefusedBeforeAnyPortIsRead:
    def refused(self, tmp_path: Path, args: list[str], match: str, **manifest: object) -> None:
        with pytest.raises(InstallRefused, match=match):
            Repository.plan(tmp_path, args, dependencies=["zlib"], **manifest)

    def test_a_manifest_without_a_baseline_is_refused(self, tmp_path: Path) -> None:
        clone, commit = Repository.make(tmp_path)
        project = Repository.project(tmp_path, commit)
        document = json.loads((project / "vcpkg.json").read_text(encoding="utf-8"))
        del document["builtin-baseline"]
        (project / "vcpkg.json").write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(InstallRefused, match="no builtin-baseline"):
            VcpkgPlanner.plan(["install"], project, lambda b: VcpkgPorts(clone, b))

    def test_a_baseline_the_clone_does_not_hold_is_refused(self, tmp_path: Path) -> None:
        clone, _ = Repository.make(tmp_path)
        project = Repository.project(tmp_path, "a" * 40, dependencies=["zlib"])
        with pytest.raises(InstallRefused, match="does not hold the baseline commit"):
            VcpkgPlanner.plan(["install"], project, lambda b: VcpkgPorts(clone, b))

    def test_classic_mode_is_refused(self, tmp_path: Path) -> None:
        self.refused(tmp_path, ["install", "zlib"], "classic mode")

    def test_overrides_are_refused(self, tmp_path: Path) -> None:
        self.refused(
            tmp_path, ["install"], "overrides", overrides=[{"name": "zlib", "version": "1.3"}]
        )

    def test_another_source_of_ports_is_refused(self, tmp_path: Path) -> None:
        self.refused(tmp_path, ["install", "--overlay-ports=/x"], "overlay-ports")

    def test_a_registry_in_the_configuration_is_refused(self, tmp_path: Path) -> None:
        self.refused(
            tmp_path, ["install"], "registries", **{"vcpkg-configuration": {"registries": []}}
        )

    @pytest.mark.parametrize(
        ("args", "installs"),
        [(["install"], True), (["--debug", "install"], True), (["list"], False), ([], False)],
    )
    def test_which_commands_build_ports(self, args: list[str], installs: bool) -> None:
        assert VcpkgPlanner.installs(args) is installs


class TestWhatVcpkgIsAllowedToUse:
    def test_the_scanned_archives_are_named_by_their_sha512_and_every_other_origin_is_blocked(
        self, tmp_path: Path
    ) -> None:
        plan = Repository.plan(tmp_path, ["install"], dependencies=["zlib"])
        files = tmp_path / "files"
        files.mkdir()
        (files / plan.files[0].filename).write_bytes(b"scanned bytes")
        seed = tmp_path / "assets"
        VcpkgPlanner.seed(plan, files, seed)
        assert [p.name for p in seed.iterdir()] == [ZLIB_SHA512]
        env = VcpkgPlanner.environment(seed, {"PATH": "/bin"})
        assert env["X_VCPKG_ASSET_SOURCES"] == f"clear;x-azurl,{seed.as_uri()},,read;x-block-origin"
        assert env["VCPKG_BINARY_SOURCES"] == "clear"

    def test_a_person_set_overlay_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="VCPKG_OVERLAY_PORTS"):
            VcpkgPlanner.environment(tmp_path, {"VCPKG_OVERLAY_PORTS": "/x"})
