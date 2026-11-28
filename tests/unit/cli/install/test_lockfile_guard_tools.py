"""The guarded installs that scan what a lock pins and then run the real tool (bazel, pod, julia, nix,
swift, Rscript, cabal, mix, code, docker, brew, terraform): each runs the tool only after a clean
verdict, and a block runs nothing and exits 1 (`cli/commands/install/`)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from install_kit import GuardKit

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, Subprocesses


class TestLockedTools:
    """bazel, pod, julia, nix and swift: plan from the lock, scan, then run with their pinning flags."""

    @staticmethod
    def tools() -> list[tuple[str, Any, Any, str]]:
        from cordon_scanner.cli.commands.install.locked.bazel import BazelTools
        from cordon_scanner.cli.commands.install.locked.cocoapods import CocoaPodsTools
        from cordon_scanner.cli.commands.install.locked.julia import JuliaTools
        from cordon_scanner.cli.commands.install.locked.nix import NixTools
        from cordon_scanner.cli.commands.install.locked.swift import SwiftTools
        from cordon_scanner.sources.install.managers.bazel import BazelPlanner
        from cordon_scanner.sources.install.managers.cocoapods import CocoaPodsPlanner
        from cordon_scanner.sources.install.managers.julia import JuliaPlanner
        from cordon_scanner.sources.install.managers.nix import NixPlanner
        from cordon_scanner.sources.install.managers.swift import SwiftPlanner

        return [
            ("bazel", BazelTools.bazel, BazelPlanner, "arguments"),
            ("pod", CocoaPodsTools.pod, CocoaPodsPlanner, "arguments"),
            ("julia", JuliaTools.julia, JuliaPlanner, ""),
            ("nix", NixTools.nix, NixPlanner, "arguments"),
            ("swift", SwiftTools.swift, SwiftPlanner, "arguments"),
        ]

    @pytest.mark.parametrize("index", range(5))
    def test_a_clean_lock_runs_the_tool_in_the_project(
        self, index: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        name, entry, planner, arguments_name = self.tools()[index]
        monkeypatch.chdir(tmp_path)
        plan = InstallPlan("test", [GuardKit.file()])
        GuardKit.stub(monkeypatch, planner, "plan", lambda *a, **k: plan)
        if arguments_name:
            GuardKit.stub(monkeypatch, planner, arguments_name, lambda args: ["--pinned", *args])
        context = GuardKit.context(code=7)
        assert entry(f"/bin/{name}", ["build"], context) == 7
        expected = [f"/bin/{name}", *(["--pinned"] if arguments_name else []), "build"]
        assert context.ran == [(expected, Path.cwd(), None)]
        assert context.checked == [plan]

    @pytest.mark.parametrize("index", range(5))
    def test_a_blocked_lock_runs_nothing(
        self, index: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        name, entry, planner, _ = self.tools()[index]
        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, planner, "plan", lambda *a, **k: InstallPlan("test"))
        context = GuardKit.context(blocks=True)
        assert entry(f"/bin/{name}", ["build"], context) == 1
        assert context.ran == []
        assert "install BLOCKED" in GuardKit.said(context)

    def test_each_tool_guards_the_command_lines_its_planner_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
        from cordon_scanner.cli.commands.install.image import ImageTools
        from cordon_scanner.cli.commands.install.locked.bazel import BazelTools
        from cordon_scanner.cli.commands.install.locked.cocoapods import CocoaPodsTools
        from cordon_scanner.cli.commands.install.locked.cran import CranTools
        from cordon_scanner.cli.commands.install.locked.hackage import HackageTools
        from cordon_scanner.cli.commands.install.locked.julia import JuliaTools
        from cordon_scanner.cli.commands.install.locked.nix import NixTools
        from cordon_scanner.cli.commands.install.locked.swift import SwiftTools
        from cordon_scanner.cli.commands.install.vscode import VscodeTools
        from cordon_scanner.sources.install.managers.cran import CranPlanner
        from cordon_scanner.sources.install.managers.hackage import HackagePlanner
        from cordon_scanner.sources.install.managers.hex import HexPlanner
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner
        from cordon_scanner.sources.install.managers.image import ImagePlanner
        from cordon_scanner.sources.install.managers.vscode import VscodePlanner

        planners = [planner for _, _, planner, _ in self.tools()] + [
            CranPlanner,
            HackagePlanner,
            HexPlanner,
            HomebrewPlanner,
            ImagePlanner,
            VscodePlanner,
        ]
        guards = (
            BazelTools,
            CocoaPodsTools,
            JuliaTools,
            NixTools,
            SwiftTools,
            CranTools,
            HackageTools,
            HexTools,
            HomebrewTools,
            ImageTools,
            VscodeTools,
        )
        for planner, guard in zip(planners, guards, strict=True):
            GuardKit.stub(monkeypatch, planner, "installs", lambda args: args == ["yes"])
            assert guard.installs(["yes"]) is True
            assert guard.installs(["no"]) is False

    def test_bazel_and_pod_fetch_only_through_the_admitted_registry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.bazel import BazelTools
        from cordon_scanner.cli.commands.install.locked.cocoapods import CocoaPodsTools
        from cordon_scanner.sources.install.managers.bazel import BazelPlanner
        from cordon_scanner.sources.install.managers.cocoapods import CocoaPodsPlanner

        monkeypatch.chdir(tmp_path)
        context = GuardKit.context()
        asked: list[tuple[str, str]] = []
        context.registries = SimpleNamespace(  # type: ignore[assignment]
            admit=lambda eco, url, label: asked.append((eco, url)) or url,
            fetch=lambda url, eco: f"{eco}|{url}".encode(),
        )
        seen: list[bytes] = []

        def bazel_plan(project: Path, fetch: Any) -> InstallPlan:
            seen.append(fetch("https://bcr.example.invalid/m"))
            return InstallPlan("bazel")

        def pod_plan(args: Any, project: Path, fetch: Any) -> InstallPlan:
            seen.append(fetch("https://cdn.example.invalid/p"))
            return InstallPlan("cocoapods")

        GuardKit.stub(monkeypatch, BazelPlanner, "plan", bazel_plan)
        GuardKit.stub(monkeypatch, CocoaPodsPlanner, "plan", pod_plan)
        BazelTools.bazel("bazel", [], context)
        CocoaPodsTools.pod("pod", ["install"], context)
        assert asked == [
            ("bazel", "https://bcr.example.invalid/m"),
            ("cocoapods", "https://cdn.example.invalid/p"),
        ]
        assert seen == [
            b"bazel|https://bcr.example.invalid/m",
            b"cocoapods|https://cdn.example.invalid/p",
        ]


class TestRscript:
    @staticmethod
    def _plan(monkeypatch: pytest.MonkeyPatch, algorithm: str) -> None:
        from cordon_scanner.sources.install.managers.cran import CranPlanner

        plan = InstallPlan("cran", [GuardKit.file("pkg", algorithm)])
        GuardKit.stub(monkeypatch, CranPlanner, "plan", lambda args, project, fetch: plan)

    def test_a_package_held_only_to_an_md5_carries_the_registry_note(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.cran import CranTools
        from cordon_scanner.sources.install.managers.cran import CranPlanner

        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, "md5")
        context = GuardKit.context()
        assert CranTools.rscript("/bin/Rscript", ["-e", "x"], context) == 0
        assert CranPlanner.NOTE in capsys.readouterr().err
        assert context.ran == [(["/bin/Rscript", "-e", "x"], Path.cwd(), None)]

    def test_a_sha256_pinned_package_prints_no_note_and_a_block_runs_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.cran import CranTools
        from cordon_scanner.sources.install.managers.cran import CranPlanner

        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, "sha256")
        context = GuardKit.context(blocks=True)
        assert CranTools.rscript("/bin/Rscript", [], context) == 1
        assert CranPlanner.NOTE not in capsys.readouterr().err
        assert context.ran == []

    def test_a_lookup_fetches_through_the_cran_archive_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.cran import CranTools
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.sources.install.managers.cran import CranPlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, ArchiveFetch, "located", lambda src, n, v: f"{n}-{v}")
        found: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            CranPlanner,
            "plan",
            lambda args, project, fetch: found.append(fetch("jsonlite", "1.8")) or InstallPlan("c"),
        )
        CranTools.rscript("Rscript", [], GuardKit.context())
        assert found == ["jsonlite-1.8"]

    def test_without_a_cran_source_nothing_is_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.cran import CranTools
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, ArchiveSources, "of", lambda eco: None)
        with pytest.raises(InstallRefused, match="no archive source"):
            CranTools.rscript("Rscript", [], GuardKit.context())


class TestHackage:
    @staticmethod
    def _cabal_world(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, context: Any
    ) -> tuple[list[str], list[Any]]:
        from cordon_scanner.sources.install.managers import hackage_index as index_module
        from cordon_scanner.sources.install.managers import hackage_repository as repo_module
        from cordon_scanner.sources.install.managers import hackage_trust as trust_module
        from cordon_scanner.sources.install.managers.hackage import HackagePlanner

        monkeypatch.chdir(tmp_path)
        fetched: list[str] = []
        context.registries = SimpleNamespace(  # type: ignore[assignment]
            admit=lambda eco, url, label: url,
            fetch=lambda url, eco: fetched.append(url) or b"{}",
        )
        plan = InstallPlan("hackage", [GuardKit.file("text")])

        def make_plan(args: Any, project: Path, hashes: Any) -> InstallPlan:
            assert hashes({("text", "1.0")}) == {("text", "1.0"): {"sha256": "ab"}}
            return plan

        GuardKit.stub(monkeypatch, HackagePlanner, "plan", make_plan)
        GuardKit.stub(monkeypatch, trust_module.HackageTrust, "index", lambda *a, **k: "facts")
        index = index_module.HackageIndex
        GuardKit.stub(monkeypatch, index, "current", lambda cache, facts: tmp_path / "ix")
        GuardKit.stub(
            monkeypatch, index, "targets", lambda path, wanted: {("text", "1.0"): {"sha256": "ab"}}
        )
        GuardKit.stub(
            monkeypatch, index, "entries", lambda path, wanted, pattern: {"wanted": sorted(wanted)}
        )
        built: list[Any] = []
        repo = repo_module.HackageRepository
        GuardKit.stub(
            monkeypatch,
            repo,
            "build",
            lambda p, files, entries, repository: built.append((entries, repository.name)),
        )
        GuardKit.stub(monkeypatch, repo, "config", lambda repository: "cfg")
        GuardKit.stub(monkeypatch, repo, "arguments", lambda args, config: ["--config", *args])
        return fetched, built

    def test_cabal_updates_then_builds_from_the_scanned_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.hackage import HackageTools

        context = GuardKit.context()
        fetched, built = self._cabal_world(tmp_path, monkeypatch, context)
        assert HackageTools.cabal("/bin/cabal", ["build"], context) == 0
        assert [argv for argv, _, _ in context.ran] == [
            ["/bin/cabal", "--config", "update"],
            ["/bin/cabal", "--config", "build"],
        ]
        assert built == [({"wanted": [("text", "1.0")]}, "repository")]
        assert fetched == [
            f"https://hackage.haskell.org/{name}.json" for name in ("root", "timestamp", "snapshot")
        ]

    def test_a_failed_index_update_stops_the_build_with_its_exit_code(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.hackage import HackageTools

        context = GuardKit.context(code=3)
        self._cabal_world(tmp_path, monkeypatch, context)
        assert HackageTools.cabal("cabal", ["build"], context) == 3
        assert [argv[2] for argv, _, _ in context.ran] == ["update"]

    def test_a_blocked_package_stops_before_any_repository_is_built(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.hackage import HackageTools
        from cordon_scanner.sources.install.managers.hackage import HackagePlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, HackagePlanner, "plan", lambda a, p, h: InstallPlan("hackage"))
        context = GuardKit.context(blocks=True)
        assert HackageTools.cabal("cabal", ["build"], context) == 1
        assert context.ran == []

    def test_the_index_is_cached_under_the_cordon_cache_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.locked.hackage import HackageTools

        monkeypatch.delenv("CORDON_CACHE_DIR", raising=False)
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert HackageTools.cache() == tmp_path / ".cache" / "cordon"
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert HackageTools.cache() == tmp_path / "xdg" / "cordon"
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "own"))
        assert HackageTools.cache() == tmp_path / "own"


class TestMix:
    @staticmethod
    def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "mix.lock").write_text("%{}", encoding="utf-8")

    def test_a_clean_pinned_project_seeds_the_cache_and_runs_mix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.sources.install.managers.hex import HexPlanner

        self._project(tmp_path, monkeypatch)
        GuardKit.subprocess_says(monkeypatch, 0, "* plug")
        plan = InstallPlan("hex", [GuardKit.file("plug")])
        GuardKit.stub(monkeypatch, HexPlanner, "plan", lambda args, project: plan)
        GuardKit.stub(monkeypatch, HexPlanner, "unpinned", lambda out, lock: [])
        GuardKit.stub(monkeypatch, HexPlanner, "cache", lambda: tmp_path / "hexcache")
        seeded: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            HexPlanner,
            "seed",
            lambda files, fetched, cache: seeded.append((files, cache)),
        )
        context = GuardKit.context(code=4)
        assert HexTools.mix("/bin/mix", ["deps.get"], context) == 4
        assert seeded == [(plan.files, tmp_path / "hexcache")]
        assert context.ran == [(["/bin/mix", "deps.get"], Path.cwd(), None)]

    def test_a_blocked_package_is_not_seeded_and_mix_does_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.sources.install.managers.hex import HexPlanner

        self._project(tmp_path, monkeypatch)
        GuardKit.subprocess_says(monkeypatch, 0)
        GuardKit.stub(monkeypatch, HexPlanner, "plan", lambda args, project: InstallPlan("hex"))
        GuardKit.stub(monkeypatch, HexPlanner, "unpinned", lambda out, lock: [])
        context = GuardKit.context(blocks=True)
        assert HexTools.mix("mix", ["deps.get"], context) == 1
        assert context.ran == []

    def test_a_project_whose_deps_cannot_be_listed_is_refused_with_mixs_words(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.sources.install.managers.hex import HexPlanner

        self._project(tmp_path, monkeypatch)
        GuardKit.subprocess_says(monkeypatch, 1, "", "no mix.exs here")
        GuardKit.stub(monkeypatch, HexPlanner, "plan", lambda args, project: InstallPlan("hex"))
        with pytest.raises(InstallRefused, match=r"(?s)could not list.*no mix\.exs here"):
            HexTools.mix("mix", ["deps.get"], GuardKit.context())

    def test_a_dependency_the_lock_does_not_pin_is_refused_by_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.sources.install.managers.hex import HexPlanner

        self._project(tmp_path, monkeypatch)
        GuardKit.subprocess_says(monkeypatch, 0, "* jason")
        GuardKit.stub(monkeypatch, HexPlanner, "plan", lambda args, project: InstallPlan("hex"))
        GuardKit.stub(monkeypatch, HexPlanner, "unpinned", lambda out, lock: ["jason"])
        context = GuardKit.context()
        with pytest.raises(InstallRefused, match="does not pin jason"):
            HexTools.mix("mix", ["deps.get"], context)
        assert context.ran == []


class TestEditorExtensions:
    def test_each_scanned_package_is_installed_by_file_after_a_clean_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.vscode import VscodeTools
        from cordon_scanner.sources.install.managers.vscode import VscodePlanner

        result = SimpleNamespace(
            plan=InstallPlan("openvsx"),
            packages=(tmp_path / "a.vsix", tmp_path / "b.vsix"),
            rest=("--force",),
        )
        GuardKit.stub(monkeypatch, VscodePlanner, "plan", lambda args, into: result)
        context = GuardKit.context()
        assert VscodeTools.code("/bin/code", ["--install-extension", "x"], context) == 0
        flag = "--install-extension"
        assert context.ran == [
            (
                [
                    "/bin/code",
                    "--force",
                    flag,
                    str(tmp_path / "a.vsix"),
                    flag,
                    str(tmp_path / "b.vsix"),
                ],
                None,
                None,
            )
        ]

    def test_a_blocked_extension_is_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cli.commands.install.vscode import VscodeTools
        from cordon_scanner.sources.install.managers.vscode import VscodePlanner

        result = SimpleNamespace(plan=InstallPlan("openvsx"), packages=(), rest=())
        GuardKit.stub(monkeypatch, VscodePlanner, "plan", lambda args, into: result)
        context = GuardKit.context(blocks=True)
        assert VscodeTools.code("code", ["--install-extension", "x"], context) == 1
        assert context.ran == []


class TestImages:
    @staticmethod
    def _planner(monkeypatch: pytest.MonkeyPatch, verb: str, platform: str = "") -> None:
        from cordon_scanner.sources.install.managers.image import ImagePlanner

        command = SimpleNamespace(verb=verb, platform=platform)
        image = SimpleNamespace(name="alpine")
        GuardKit.stub(monkeypatch, ImagePlanner, "locate", lambda args: command)
        GuardKit.stub(
            monkeypatch,
            ImagePlanner,
            "plan",
            lambda cmd, daemon, layout: (InstallPlan("oci"), image, "sha256:d"),
        )
        GuardKit.stub(monkeypatch, ImagePlanner, "pinned", lambda img, digest: "alpine@" + digest)
        GuardKit.stub(
            monkeypatch, ImagePlanner, "arguments", lambda args, cmd, pinned: [*args[:1], pinned]
        )
        GuardKit.stub(monkeypatch, ImagePlanner, "tagged", lambda img: "alpine:3")

    def test_a_pull_runs_by_digest_then_restores_the_tag_that_was_asked_for(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.image import ImageTools

        self._planner(monkeypatch, "pull", platform="linux/arm64")
        context = GuardKit.context()
        assert ImageTools.docker("/bin/docker", ["pull", "alpine:3"], context) == 0
        assert [argv for argv, _, _ in context.ran] == [
            ["/bin/docker", "pull", "alpine@sha256:d"],
            ["/bin/docker", "tag", "alpine@sha256:d", "alpine:3"],
        ]

    def test_a_run_is_pinned_and_gets_no_tag_and_a_failed_pull_leaves_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.image import ImageTools

        self._planner(monkeypatch, "run", platform="linux/amd64")
        context = GuardKit.context()
        assert ImageTools.docker("docker", ["run", "alpine"], context) == 0
        assert len(context.ran) == 1
        self._planner(monkeypatch, "pull", platform="linux/amd64")
        failing = GuardKit.context(code=125)
        assert ImageTools.docker("docker", ["pull", "alpine"], failing) == 125
        assert len(failing.ran) == 1, "no tag is made for an image that was not pulled"

    def test_a_blocked_image_is_not_pulled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cli.commands.install.image import ImageTools

        self._planner(monkeypatch, "pull", platform="linux/amd64")
        context = GuardKit.context(blocks=True)
        assert ImageTools.docker("docker", ["pull", "alpine"], context) == 1
        assert context.ran == []

    def test_the_platform_is_asked_of_the_runtime_when_the_command_names_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.image import ImageTools
        from cordon_scanner.sources.install.managers.image import ImagePlanner

        self._planner(monkeypatch, "pull", platform="")
        asked: list[Any] = []

        def plan(cmd: Any, daemon: str, layout: Path) -> Any:
            asked.append(daemon)
            return InstallPlan("oci"), SimpleNamespace(name="a"), "d"

        GuardKit.stub(monkeypatch, ImagePlanner, "plan", plan)
        GuardKit.stub(monkeypatch, ImagePlanner, "tagged", lambda img: None)
        GuardKit.subprocess_says(monkeypatch, 0, " linux/arm64\n")
        ImageTools.docker("/usr/bin/docker", ["pull", "alpine"], GuardKit.context())
        assert asked == ["linux/arm64"]

    def test_a_runtime_that_will_not_say_or_is_unknown_gives_an_empty_platform(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.image import ImageTools

        GuardKit.subprocess_says(monkeypatch, 1, "x")
        assert ImageTools.platform("/usr/bin/podman") == ""
        assert ImageTools.platform("/usr/bin/nerdctl") == ""
        GuardKit.subprocess_says(monkeypatch, 0, "linux/arm64\n")
        assert ImageTools.platform("/usr/bin/podman.exe") == "linux/arm64"


class TestBrew:
    def test_the_formula_data_is_pinned_and_the_install_runs_after_a_clean_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner

        seen: list[str] = []

        def plan(args: Any, bottles: Path, ask: Any) -> Any:
            seen.append(ask(["info", "--json=v2", "jq"]))
            return SimpleNamespace(plan=InstallPlan("brew"), formulae=("jq",))

        GuardKit.stub(monkeypatch, HomebrewPlanner, "plan", plan)

        def run(argv: Any, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                argv, 0, f"{argv[0]}:{env['HOMEBREW_NO_AUTO_UPDATE']}", ""
            )

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        context = GuardKit.context()
        assert HomebrewTools.brew("/bin/brew", ["install", "jq"], context) == 0
        assert seen == ["/bin/brew:1"]
        argv, _, env = context.ran[0]
        assert argv == ["/bin/brew", "install", "jq"]
        assert env is not None and env["HOMEBREW_NO_AUTO_UPDATE"] == "1"

    def test_brew_that_cannot_resolve_is_refused_with_its_own_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner

        GuardKit.stub(
            monkeypatch, HomebrewPlanner, "plan", lambda args, bottles, ask: ask(["info", "jq"])
        )
        GuardKit.subprocess_says(monkeypatch, 1, "", "no such formula")
        with pytest.raises(
            InstallRefused, match=r"(?s)`brew info` could not resolve.*no such formula"
        ):
            HomebrewTools.brew("brew", ["install", "x"], GuardKit.context())

    def test_a_blocked_bottle_is_not_poured_and_an_unplanned_command_runs_as_typed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner

        result = SimpleNamespace(plan=InstallPlan("brew"), formulae=())
        GuardKit.stub(monkeypatch, HomebrewPlanner, "plan", lambda args, b, ask: result)
        blocked = GuardKit.context(blocks=True)
        assert HomebrewTools.brew("brew", ["install", "x"], blocked) == 1
        assert blocked.ran == []
        nothing = SimpleNamespace(plan=None, formulae=())
        GuardKit.stub(monkeypatch, HomebrewPlanner, "plan", lambda args, b, ask: nothing)
        context = GuardKit.context()
        assert HomebrewTools.brew("brew", ["upgrade"], context) == 0
        assert context.checked == [] and len(context.ran) == 1


class TestFetchedTrees:
    def test_the_tool_runs_as_typed_and_what_it_wrote_is_scanned_by_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.fetched import FetchedTools
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        monkeypatch.chdir(tmp_path)
        outcome: list[Any] = []

        def run(name: str, args: Any, cwd: Path, fetch: Any, scan: Any, scratch: Path) -> int:
            outcome.append((name, fetch(), scan(tmp_path), scan(tmp_path)))
            return 5

        GuardKit.stub(monkeypatch, FetchedTree, "run", run)
        context = GuardKit.context(code=9)
        assert FetchedTools.run("/usr/bin/terraform", ["init"], context) == 5
        assert outcome == [("terraform", 9, True, True)]
        assert context.checked[0].ecosystem == "terraform"
        assert context.checked[0].local == [tmp_path]

    def test_a_block_is_reported_and_the_scan_says_no(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.fetched import FetchedTools
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        monkeypatch.chdir(tmp_path)
        verdicts: list[bool] = []
        GuardKit.stub(
            monkeypatch,
            FetchedTree,
            "run",
            lambda name, args, cwd, fetch, scan, scratch: verdicts.append(scan(tmp_path)) or 1,
        )
        context = GuardKit.context(blocks=True)
        assert FetchedTools.run("helm", ["pull", "x"], context) == 1
        assert verdicts == [False]
        assert "install BLOCKED" in GuardKit.said(context)

    def test_which_command_lines_each_tool_guards_follows_the_fetch_rules(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.fetched import FetchedTools
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        asked: list[str] = []
        GuardKit.stub(
            monkeypatch, FetchedTree, "installs", lambda tool, args: asked.append(tool) or True
        )
        assert FetchedTools.terraform_installs(["init"])
        assert FetchedTools.helm_installs(["pull"])
        assert FetchedTools.galaxy_installs(["install"])
        assert asked == ["terraform", "helm", "ansible-galaxy"]
