"""cargo, go, gem, bundle, pub, conda, npm, pnpm, yarn, composer, dotnet and mvn through Cordon: the tool
runs only on what was scanned, and a block puts the project back as it was (`cli/commands/install/`)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from install_kit import GuardKit

from cordon_scanner.cli.commands.install.native import NativeTools
from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, Subprocesses


class TestCargo:
    @staticmethod
    def _planner(monkeypatch: pytest.MonkeyPatch, plan: InstallPlan, restored: list[Any]) -> None:
        from cordon_scanner.sources.install.cargo import CargoPlanner

        GuardKit.stub(monkeypatch, CargoPlanner, "project", lambda verb, args, run, c, p: plan)
        GuardKit.stub(
            monkeypatch, CargoPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        GuardKit.stub(monkeypatch, CargoPlanner, "locked", lambda verb, args: [verb, "--locked"])

    def test_a_clean_build_runs_cargo_locked_against_the_scanned_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        self._planner(monkeypatch, InstallPlan("crates", [GuardKit.file()]), restored)
        context = GuardKit.context(code=2)
        assert NativeTools.cargo("/bin/cargo", ["build"], context) == 2
        assert context.ran == [(["/bin/cargo", "build", "--locked"], Path.cwd(), None)]
        assert restored == []

    def test_a_blocked_build_puts_the_manifests_back_and_runs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        plan = InstallPlan("crates", manifests={"saved:Cargo.lock": b"old", "Cargo.lock": b"new"})
        self._planner(monkeypatch, plan, restored)
        context = GuardKit.context(blocks=True)
        assert NativeTools.cargo("cargo", ["build"], context) == 1
        assert restored == [{"Cargo.lock": b"old"}]
        assert context.ran == []

    def test_a_refusal_while_checking_also_puts_the_manifests_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        plan = InstallPlan("crates", manifests={"saved:Cargo.lock": b"old"})
        self._planner(monkeypatch, plan, restored)
        context = GuardKit.context()

        def refuse(plan: InstallPlan, scratch: Path) -> Any:
            raise InstallRefused("hash does not match")

        context.check = refuse  # type: ignore[method-assign]
        with pytest.raises(InstallRefused, match="does not match"):
            NativeTools.cargo("cargo", ["build"], context)
        assert restored == [{"Cargo.lock": b"old"}]

    def test_the_options_of_an_install_are_split_from_its_crate_and_version(self) -> None:
        names, options, version = NativeTools._cargo_install_args(
            ["ripgrep@14", "--locked", "--features", "pcre2", "-F=simd", "--debug", "--vers=14.1"]
        )
        assert (names, options, version) == (
            ["ripgrep@14"],
            ["--features", "pcre2", "-F=simd", "--debug"],
            "14.1",
        )
        assert NativeTools._cargo_install_args(["x", "--version", "2"])[2] == "2"
        assert NativeTools._cargo_install_args(["x", "--version"])[2] == ""

    def test_an_install_from_a_path_or_git_is_a_local_build(self) -> None:
        assert NativeTools._local_install(["--path", "."])
        assert NativeTools._local_install(["x", "--git=https://example.invalid/r"])
        assert not NativeTools._local_install(["ripgrep"])

    def test_a_clean_crate_is_built_from_the_scanned_archive_and_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.cargo import CargoPlanner, CrateArchive

        crate = GuardKit.file("ripgrep")
        plan = InstallPlan("crates", [crate], manifests={"Cargo.lock": b"lock-bytes"})
        planned: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            CargoPlanner,
            "install",
            lambda spec, version, run, cargo, scratch: planned.append((spec, version)) or plan,
        )
        root = tmp_path / "src-root"
        root.mkdir()
        GuardKit.stub(monkeypatch, CrateArchive, "extract", lambda archive, into: root)
        context = GuardKit.context(code=3)
        monkeypatch.chdir(tmp_path)
        code = NativeTools.cargo(
            "/bin/cargo", ["install", "ripgrep@14", "--features", "pcre2", "--locked"], context
        )
        assert code == 3
        assert planned == [("ripgrep", "14")]
        assert (root / "Cargo.lock").read_bytes() == b"lock-bytes"
        assert context.ran == [
            (
                ["/bin/cargo", "install", "--path", str(root), "--locked", "--features", "pcre2"],
                None,
                None,
            )
        ]

    def test_a_blocked_crate_is_not_built_and_a_second_name_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.cargo import CargoPlanner

        plan = InstallPlan("crates", [GuardKit.file("ripgrep")])
        GuardKit.stub(monkeypatch, CargoPlanner, "install", lambda *a: plan)
        monkeypatch.chdir(tmp_path)
        context = GuardKit.context(blocks=True)
        assert NativeTools.cargo("cargo", ["install", "ripgrep"], context) == 1
        assert context.ran == []
        with pytest.raises(InstallRefused, match="one crate at a time"):
            NativeTools.cargo("cargo", ["install", "a", "b"], GuardKit.context())


class TestGo:
    def test_a_module_get_is_scanned_and_the_restore_runs_on_a_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gomod import GoPlanner

        monkeypatch.chdir(tmp_path)
        seen: list[Any] = []
        restored: list[Any] = []
        plan = InstallPlan("go", manifests={"saved:go.sum": b"old"})
        GuardKit.stub(
            monkeypatch,
            GoPlanner,
            "module",
            lambda verb, args, run, go, project: seen.append((verb, args)) or plan,
        )
        GuardKit.stub(
            monkeypatch, GoPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        blocked = GuardKit.context(blocks=True)
        assert NativeTools.go("go", ["get", "example.com/m@v1"], blocked) == 1
        assert seen == [("get", ["example.com/m@v1"])]
        assert restored == [{"go.sum": b"old"}]
        clean = GuardKit.context()
        assert NativeTools.go("go", ["get", "example.com/m@v1"], clean) == 0
        assert clean.ran == [], "`go get` itself is replaced by the scanned resolve"

    def test_a_build_command_runs_as_typed_after_the_download_is_scanned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gomod import GoPlanner

        monkeypatch.chdir(tmp_path)
        seen: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            GoPlanner,
            "module",
            lambda verb, args, run, go, project: seen.append(verb) or InstallPlan("go"),
        )
        context = GuardKit.context(code=6)
        assert NativeTools.go("/bin/go", ["mod", "download"], context) == 6
        assert seen == ["download"]
        assert context.ran == [(["/bin/go", "mod", "download"], Path.cwd(), None)]

    def test_go_install_of_a_versioned_path_resolves_in_a_private_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gomod import GoPlanner

        monkeypatch.chdir(tmp_path)
        commands: list[list[str]] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            commands.append(list(argv))
            assert cwd != tmp_path, "the resolve happens away from the project"
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        resolved: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            GoPlanner,
            "module",
            lambda verb, args, run, go, project: (
                resolved.append((verb, args, project.name)) or InstallPlan("go")
            ),
        )
        context = GuardKit.context()
        args = ["install", "example.com/tool@v1.2.3"]
        assert NativeTools.go("/bin/go", args, context) == 0
        assert commands == [["/bin/go", "mod", "init", "cordon.invalid/resolve"]]
        assert resolved[0][:2] == ("get", ["example.com/tool@v1.2.3"])
        assert context.ran == [(["/bin/go", *args], Path.cwd(), None)]

    def test_which_go_and_cargo_lines_install(self) -> None:
        assert NativeTools.go_installs(["mod", "download"])
        assert not NativeTools.go_installs(["mod"])
        assert not NativeTools.go_installs(["mod", "tidy-nothing"])
        assert NativeTools.go_installs(["get", "x"])
        assert not NativeTools.go_installs(["version"])
        assert not NativeTools.go_installs([])
        assert NativeTools.cargo_installs(["build"])
        assert not NativeTools.cargo_installs([])
        assert not NativeTools.cargo_installs(["--version"])


class TestRuby:
    def test_gems_are_installed_locally_in_order_from_the_scanned_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gem import GemPlanner

        monkeypatch.chdir(tmp_path)
        files = [GuardKit.file("rack"), GuardKit.file("sinatra")]
        plan = InstallPlan("rubygems", files)
        GuardKit.stub(monkeypatch, GemPlanner, "local_options", lambda args: ["--user-install"])
        GuardKit.stub(monkeypatch, GemPlanner, "gem_install", lambda *a: plan)
        context = GuardKit.context()
        assert NativeTools.gem("/bin/gem", ["install", "sinatra"], context) == 0
        argv = context.ran[0][0]
        assert argv[:5] == [
            "/bin/gem",
            "install",
            "--local",
            "--ignore-dependencies",
            "--user-install",
        ]
        assert [Path(a).name for a in argv[5:]] == [f.filename for f in files]

    def test_a_blocked_gem_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gem import GemPlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, GemPlanner, "local_options", lambda args: [])
        GuardKit.stub(monkeypatch, GemPlanner, "gem_install", lambda *a: InstallPlan("rubygems"))
        context = GuardKit.context(blocks=True)
        assert NativeTools.gem("gem", ["install", "x"], context) == 1
        assert context.ran == []

    def test_bundler_installs_from_the_scanned_cache_then_runs_the_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gem import GemPlanner

        monkeypatch.chdir(tmp_path)
        gem = GuardKit.file("rack")
        planned: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            GemPlanner,
            "bundle",
            lambda verb, args, run, bundle, registries, project: (
                planned.append((verb, args)) or InstallPlan("rubygems", [gem])
            ),
        )
        context = GuardKit.context()
        assert NativeTools.bundle("/bin/bundle", ["exec", "rake"], context) == 0
        assert planned == [("exec", ["rake"])]
        install, run = context.ran
        assert install[0] == ["/bin/bundle", "install", "--local"]
        assert install[2] is not None and Path(install[2]["BUNDLE_CACHE_PATH"]).name
        assert run[0] == ["/bin/bundle", "exec", "rake"]

    def test_a_failed_bundle_install_stops_and_a_plain_install_runs_nothing_after(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gem import GemPlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, GemPlanner, "bundle", lambda *a: InstallPlan("rubygems"))
        failing = GuardKit.context(code=5)
        assert NativeTools.bundle("bundle", ["exec", "rake"], failing) == 5
        assert len(failing.ran) == 1
        plain = GuardKit.context()
        assert NativeTools.bundle("bundle", [], plain) == 0
        assert len(plain.ran) == 1

    def test_a_blocked_bundle_restores_the_gemfile_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.gem import GemPlanner

        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        plan = InstallPlan("rubygems", manifests={"saved:Gemfile.lock": b"old"})
        GuardKit.stub(monkeypatch, GemPlanner, "bundle", lambda *a: plan)
        GuardKit.stub(
            monkeypatch, GemPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        context = GuardKit.context(blocks=True)
        assert NativeTools.bundle("bundle", ["install"], context) == 1
        assert restored == [{"Gemfile.lock": b"old"}]
        assert context.ran == []

    def test_which_gem_and_bundle_lines_install(self) -> None:
        assert NativeTools.gem_installs(["install", "x"])
        assert not NativeTools.gem_installs(["list"])
        assert not NativeTools.gem_installs([])
        assert NativeTools.bundle_installs([]), "a bare `bundle` is `bundle install`"
        assert NativeTools.bundle_installs(["install"])
        assert not NativeTools.bundle_installs(["config"])
        assert NativeTools._gem_name("rack", "3.0") == "rack-3.0.gem"


class TestPubAndConda:
    def test_pub_runs_the_locked_command_after_a_clean_scan_and_restores_on_a_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.managers.pub import PubPlanner

        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        plan = InstallPlan("pub", manifests={"saved:pubspec.lock": b"old"})
        GuardKit.stub(monkeypatch, PubPlanner, "project", lambda args, run, tool, p, cache: plan)
        GuardKit.stub(
            monkeypatch, PubPlanner, "locked", lambda tool: [tool, "get", "--enforce-lockfile"]
        )
        GuardKit.stub(
            monkeypatch, PubPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        clean = GuardKit.context()
        assert NativeTools.pub("dart", ["pub", "get"], clean) == 0
        assert clean.ran == [(["dart", "get", "--enforce-lockfile"], Path.cwd(), None)]
        blocked = GuardKit.context(blocks=True)
        assert NativeTools.pub("dart", ["pub", "get"], blocked) == 1
        assert restored == [{"pubspec.lock": b"old"}]

    def test_which_pub_and_conda_lines_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.sources.install.managers.conda import CondaPlanner
        from cordon_scanner.sources.install.managers.pub import PubPlanner

        GuardKit.stub(monkeypatch, PubPlanner, "installs", lambda args: args == ["get"])
        GuardKit.stub(monkeypatch, CondaPlanner, "installs", lambda args: args == ["install"])
        assert NativeTools.pub_installs(["get"]) and not NativeTools.pub_installs(["run"])
        assert NativeTools.conda_installs(["install"]) and not NativeTools.conda_installs(["list"])

    def _conda(self, monkeypatch: pytest.MonkeyPatch, files: list[Any]) -> list[Any]:
        from cordon_scanner.sources.install.managers.conda import CondaPlanner

        placed: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            CondaPlanner,
            "plan",
            lambda a, run, conda, resolve: InstallPlan("conda", files),
        )
        GuardKit.stub(monkeypatch, CondaPlanner, "package_cache", lambda run, conda: Path("/cache"))
        GuardKit.stub(
            monkeypatch,
            CondaPlanner,
            "place",
            lambda fs, scanned, cache: placed.append((len(fs), cache)),
        )
        GuardKit.stub(monkeypatch, CondaPlanner, "explicit", lambda fs, scanned: "@EXPLICIT\n")
        GuardKit.stub(
            monkeypatch,
            CondaPlanner,
            "explicit_command",
            lambda args, spec: [*args, "--file", spec.read_text(encoding="utf-8").strip()],
        )
        return placed

    def test_conda_links_only_the_scanned_files_from_an_explicit_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        placed = self._conda(monkeypatch, [GuardKit.file("numpy")])
        context = GuardKit.context()
        assert NativeTools.conda("/bin/conda", ["install", "numpy"], context) == 0
        assert context.ran == [
            (["/bin/conda", "install", "numpy", "--file", "@EXPLICIT"], None, None)
        ]
        assert placed == [(1, Path("/cache"))]

    def test_conda_with_nothing_to_fetch_runs_as_typed_and_a_block_runs_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._conda(monkeypatch, [])
        nothing = GuardKit.context()
        assert NativeTools.conda("conda", ["install", "numpy"], nothing) == 0
        assert nothing.ran == [(["conda", "install", "numpy"], None, None)]
        assert nothing.checked == []
        self._conda(monkeypatch, [GuardKit.file("numpy")])
        blocked = GuardKit.context(blocks=True)
        assert NativeTools.conda("conda", ["install", "numpy"], blocked) == 1
        assert blocked.ran == []


class TestNode:
    @staticmethod
    def _plan() -> InstallPlan:
        return InstallPlan(
            "npm", [GuardKit.file("left-pad")], manifests={"package-lock.json": b"{}"}
        )

    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("npm", ["npm", "ci", "--no-audit", "--no-fund"]),
            ("pnpm", ["pnpm", "install", "--frozen-lockfile"]),
            ("yarn", ["yarn", "install", "--frozen-lockfile"]),
        ],
    )
    def test_a_clean_resolve_is_written_then_installed_frozen(
        self, tool: str, expected: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.node import NodeTools
        from cordon_scanner.sources.install.npm import NpmPlanner
        from cordon_scanner.sources.install.pnpm import PnpmPlanner
        from cordon_scanner.sources.install.yarn import YarnPlanner

        monkeypatch.chdir(tmp_path)
        for planner in (NpmPlanner, PnpmPlanner, YarnPlanner):
            GuardKit.stub(monkeypatch, planner, "plan", lambda *a: self._plan())
        GuardKit.stub(monkeypatch, YarnPlanner, "modern", lambda project, run, yarn: False)
        context = GuardKit.context(code=8)
        assert getattr(NodeTools, tool)(tool, ["install"], context) == 8
        assert context.ran == [(expected, Path.cwd(), None)]
        assert (tmp_path / "package-lock.json").read_bytes() == b"{}"

    def test_a_modern_yarn_installs_immutable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.node import NodeTools
        from cordon_scanner.sources.install.yarn import YarnPlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, YarnPlanner, "modern", lambda project, run, yarn: True)
        GuardKit.stub(monkeypatch, YarnPlanner, "plan", lambda *a: self._plan())
        context = GuardKit.context()
        NodeTools.yarn("yarn", [], context)
        assert context.ran[0][0] == ["yarn", "install", "--immutable"]

    def test_a_blocked_resolve_writes_no_lock_and_runs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.node import NodeTools
        from cordon_scanner.sources.install.npm import NpmPlanner

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, NpmPlanner, "plan", lambda *a: self._plan())
        context = GuardKit.context(blocks=True)
        assert NodeTools.npm("npm", ["install", "x"], context) == 1
        assert not (tmp_path / "package-lock.json").exists()
        assert context.ran == []

    def test_which_node_lines_install(self) -> None:
        from cordon_scanner.cli.commands.install.node import NodeTools

        assert NodeTools.npm_installs(["install"]) and not NodeTools.npm_installs(["run", "x"])
        assert not NodeTools.npm_installs([])
        assert NodeTools.pnpm_installs([]) and NodeTools.pnpm_installs(["install"])
        assert not NodeTools.pnpm_installs(["run"])
        assert NodeTools.yarn_installs([]) and NodeTools.yarn_installs(["add"])
        assert not NodeTools.yarn_installs(["run"])


class TestComposer:
    @staticmethod
    def _world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restored: list[Any]) -> Any:
        from cordon_scanner.sources.install.managers.composer import ComposerPlanner

        monkeypatch.chdir(tmp_path)
        (tmp_path / "composer.lock").write_text('{"packages": []}', encoding="utf-8")
        plan = InstallPlan(
            "composer", [GuardKit.file("monolog")], manifests={"saved:composer.lock": b"old"}
        )
        GuardKit.stub(monkeypatch, ComposerPlanner, "project", lambda *a: plan)
        GuardKit.stub(
            monkeypatch, ComposerPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        return ComposerPlanner

    def test_a_clean_install_seeds_a_cache_and_runs_composer_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.composer import ComposerTools

        restored: list[Any] = []
        planner = self._world(tmp_path, monkeypatch, restored)
        seeded: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            planner,
            "seed",
            lambda lock, files, cache, dev: seeded.append((lock, dev)),
        )
        GuardKit.stub(monkeypatch, planner, "install_command", lambda c, args: [c, "install"])
        GuardKit.stub(
            monkeypatch, planner, "offline_env", lambda cache: {"COMPOSER_HOME": str(cache)}
        )
        context = GuardKit.context()
        assert ComposerTools.composer("/bin/composer", ["install", "--no-dev"], context) == 0
        assert seeded == [({"packages": []}, False)]
        argv, cwd, env = context.ran[0]
        assert argv == ["/bin/composer", "install"] and cwd == Path.cwd()
        assert env is not None and env["COMPOSER_HOME"].endswith("cache")
        assert restored == []

    def test_a_block_or_a_failure_while_seeding_restores_composer_json_and_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.composer import ComposerTools

        restored: list[Any] = []
        planner = self._world(tmp_path, monkeypatch, restored)
        blocked = GuardKit.context(blocks=True)
        assert ComposerTools.composer("composer", ["install"], blocked) == 1
        assert restored == [{"composer.lock": b"old"}] and blocked.ran == []

        def broken(lock: Any, files: Any, cache: Any, dev: bool) -> None:
            raise InstallRefused("an archive does not match")

        GuardKit.stub(monkeypatch, planner, "seed", broken)
        with pytest.raises(InstallRefused):
            ComposerTools.composer("composer", ["install"], GuardKit.context())
        assert restored == [{"composer.lock": b"old"}] * 2

    def test_which_composer_lines_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cli.commands.install.composer import ComposerTools
        from cordon_scanner.sources.install.managers.composer import ComposerPlanner

        GuardKit.stub(monkeypatch, ComposerPlanner, "installs", lambda args: args == ["require"])
        assert ComposerTools.installs(["require"]) and not ComposerTools.installs(["show"])


class TestDotnet:
    @staticmethod
    def _nuget(monkeypatch: pytest.MonkeyPatch, restored: list[Any]) -> Any:
        from cordon_scanner.sources.install.managers.nuget import NuGetPlanner

        plan = InstallPlan(
            "nuget", [GuardKit.file("Newtonsoft")], manifests={"saved:a.csproj": b"old"}
        )
        GuardKit.stub(monkeypatch, NuGetPlanner, "project", lambda *a: plan)
        GuardKit.stub(monkeypatch, NuGetPlanner, "tool", lambda name, version, registries: plan)
        GuardKit.stub(
            monkeypatch, NuGetPlanner, "restore", lambda project, saved: restored.append(saved)
        )
        GuardKit.stub(
            monkeypatch,
            NuGetPlanner,
            "scanned_source",
            lambda files, fetched, source: source.mkdir(),
        )
        GuardKit.stub(monkeypatch, NuGetPlanner, "source_config", lambda source: "<configuration/>")
        GuardKit.stub(
            monkeypatch, NuGetPlanner, "locked", lambda args, config: [*args, "--locked-mode"]
        )
        return NuGetPlanner

    def test_a_clean_restore_runs_dotnet_in_locked_mode_against_the_scanned_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        monkeypatch.chdir(tmp_path)
        self._nuget(monkeypatch, [])
        context = GuardKit.context()
        assert DotnetTools.dotnet("/bin/dotnet", ["restore"], context) == 0
        assert context.ran == [(["/bin/dotnet", "restore", "--locked-mode"], Path.cwd(), None)]

    def test_a_blocked_restore_or_a_refusal_puts_the_project_files_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        monkeypatch.chdir(tmp_path)
        restored: list[Any] = []
        self._nuget(monkeypatch, restored)
        blocked = GuardKit.context(blocks=True)
        assert DotnetTools.dotnet("dotnet", ["restore"], blocked) == 1
        assert restored == [{"a.csproj": b"old"}] and blocked.ran == []
        refusing = GuardKit.context()

        def refuse(plan: Any, scratch: Path) -> Any:
            raise InstallRefused("hash mismatch")

        refusing.check = refuse  # type: ignore[method-assign]
        with pytest.raises(InstallRefused):
            DotnetTools.dotnet("dotnet", ["restore"], refusing)
        assert len(restored) == 2

    def test_a_tool_install_is_pinned_to_the_scanned_version_and_a_private_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        monkeypatch.chdir(tmp_path)
        self._nuget(monkeypatch, [])
        context = GuardKit.context()
        args = ["tool", "install", "--global", "dotnet-ef", "--version", "8.0.1", "-v", "q"]
        assert DotnetTools.dotnet("/bin/dotnet", args, context) == 0
        argv = context.ran[0][0]
        assert argv[:6] == ["/bin/dotnet", "tool", "install", "--global", "dotnet-ef", "-v"]
        assert argv[6:9] == ["q", "--version", "1.0"]
        assert argv[9] == "--configfile" and argv[10].endswith("nuget.config")

    def test_a_tool_install_from_another_source_or_of_two_tools_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        monkeypatch.chdir(tmp_path)
        self._nuget(monkeypatch, [])
        for option in ("--add-source", "--configfile=x.config", "-s"):
            with pytest.raises(InstallRefused, match=r"nuget\.org only"):
                DotnetTools.dotnet(
                    "dotnet", ["tool", "install", "x", option, "u"], GuardKit.context()
                )
        with pytest.raises(InstallRefused, match="one tool at a time"):
            DotnetTools.dotnet("dotnet", ["tool", "install", "a", "b"], GuardKit.context())

    def test_a_blocked_tool_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        monkeypatch.chdir(tmp_path)
        self._nuget(monkeypatch, [])
        context = GuardKit.context(blocks=True)
        assert DotnetTools.dotnet("dotnet", ["tool", "install", "x"], context) == 1
        assert context.ran == []

    def test_the_version_asked_for_is_read_in_both_spellings_and_dropped_from_the_rest(
        self,
    ) -> None:
        names, version = DotnetToolsKit.args(["x", "--version=2.0", "--tool-path", "/t", "-a", "y"])
        assert (names, version) == (["x"], "2.0")
        assert DotnetToolsKit.args(["x", "-f=net8", "--verbosity", "q"]) == (["x"], "")
        assert DotnetToolsKit.without(["a", "--version", "1", "b", "--version=2", "c"]) == [
            "a",
            "b",
            "c",
        ]

    def test_which_dotnet_lines_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools
        from cordon_scanner.sources.install.managers.nuget import NuGetPlanner

        GuardKit.stub(monkeypatch, NuGetPlanner, "installs", lambda args: args == ["restore"])
        assert DotnetTools.installs(["restore"]) and not DotnetTools.installs(["build"])


class DotnetToolsKit:
    @staticmethod
    def args(args: list[str]) -> tuple[list[str], str]:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        return DotnetTools._tool_args(args)

    @staticmethod
    def without(args: list[str]) -> list[str]:
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools

        return DotnetTools._without_value(args, "--version")


class TestMaven:
    @staticmethod
    def _world(
        monkeypatch: pytest.MonkeyPatch, runs: list[tuple[int, str]], plans: list[InstallPlan]
    ) -> Any:
        from cordon_scanner.cli.commands.install.maven import MavenTools
        from cordon_scanner.sources.install.managers.maven import MavenPlanner

        GuardKit.stub(monkeypatch, MavenPlanner, "local_repository", lambda args, project: None)
        GuardKit.stub(monkeypatch, MavenPlanner, "go_offline", lambda *a: None)
        queue = iter(plans)
        GuardKit.stub(monkeypatch, MavenPlanner, "plan", lambda repo, known: next(queue))
        GuardKit.stub(monkeypatch, MavenPlanner, "seed", lambda *a: None)
        GuardKit.stub(monkeypatch, MavenPlanner, "offline", lambda mvn, args: [mvn, "-o", *args])
        GuardKit.stub(
            monkeypatch,
            MavenPlanner,
            "missing",
            lambda output: [tuple(output.split(":"))] if output else [],
        )
        fetched: list[Any] = []
        GuardKit.stub(monkeypatch, MavenPlanner, "fetch_missing", lambda *a: fetched.append(a[0]))
        results = iter(runs)
        monkeypatch.setattr(MavenTools, "_run", staticmethod(lambda argv, cwd: next(results)))
        return fetched

    def test_a_clean_plan_builds_offline_from_the_seeded_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        monkeypatch.chdir(tmp_path)
        self._world(monkeypatch, [(0, "")], [InstallPlan("maven", [GuardKit.file("jar")])])
        context = GuardKit.context()
        assert MavenTools.mvn("mvn", ["package"], context) == 0
        assert len(context.checked) == 1

    def test_a_blocked_jar_stops_the_build(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        monkeypatch.chdir(tmp_path)
        self._world(monkeypatch, [], [InstallPlan("maven", [GuardKit.file("jar")])])
        context = GuardKit.context(blocks=True)
        assert MavenTools.mvn("mvn", ["package"], context) == 1

    def test_an_artifact_a_plugin_asks_for_is_fetched_scanned_and_the_build_run_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        monkeypatch.chdir(tmp_path)
        plans = [InstallPlan("maven"), InstallPlan("maven", [GuardKit.file("plugin")])]
        fetched = self._world(monkeypatch, [(1, "org.x:plugin:1.0"), (0, "")], plans)
        context = GuardKit.context()
        assert MavenTools.mvn("mvn", ["package"], context) == 0
        assert fetched == [[("org.x", "plugin", "1.0")]]
        assert "org.x:plugin:1.0" in capsys.readouterr().err
        assert len(context.checked) == 1, "only the round with files is scanned"

    def test_a_build_that_keeps_failing_gives_up_after_the_rounds_with_its_last_code(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        monkeypatch.chdir(tmp_path)
        rounds = MavenTools.ROUNDS
        self._world(
            monkeypatch, [(3, "a:b:c")] * rounds, [InstallPlan("maven") for _ in range(rounds)]
        )
        assert MavenTools.mvn("mvn", ["package"], GuardKit.context()) == 3

    def test_a_failure_with_nothing_missing_is_returned_at_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        monkeypatch.chdir(tmp_path)
        self._world(monkeypatch, [(2, "")], [InstallPlan("maven")])
        assert MavenTools.mvn("mvn", ["package"], GuardKit.context()) == 2

    def test_the_build_output_is_shown_as_it_runs_and_its_tail_kept(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools

        script = "import sys\nfor i in range(500):\n    print(i)\nsys.exit(4)\n"
        code, output = MavenTools._run([sys.executable, "-c", script], tmp_path)
        assert code == 4
        lines = output.splitlines()
        assert len(lines) == 400 and lines[0] == "100" and lines[-1] == "499"
        assert capsys.readouterr().out.splitlines()[0] == "0"

    def test_which_mvn_lines_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.cli.commands.install.maven import MavenTools
        from cordon_scanner.sources.install.managers.maven import MavenPlanner

        GuardKit.stub(monkeypatch, MavenPlanner, "installs", lambda args: args == ["package"])
        assert MavenTools.installs(["package"]) and not MavenTools.installs(["help"])
