"""pip, uv and poetry through Cordon, the pip planner's callbacks and the build retry
(`cli/commands/install/python.py`, `uv_install.py`, `python_hooks.py`): the scanned files alone are
installed, hashes pinned, and a block installs nothing."""

from __future__ import annotations

import io
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from install_kit import GuardKit

from cordon_scanner.cli.commands.install.context import SdistBlocked
from cordon_scanner.cli.commands.install.python import PythonTools
from cordon_scanner.cli.commands.install.python_hooks import BuildRetry, PythonHooks
from cordon_scanner.cli.commands.install.uv_install import UvInstall
from cordon_scanner.sources.install.pip import PipPlanner
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PackageFile,
    Subprocesses,
)


class _Kit:
    @staticmethod
    def wheel(name: str, build_only: bool = False) -> PackageFile:
        return PackageFile(
            "pypi",
            name,
            "1.0",
            f"https://files.example.invalid/{name}-1.0-py3-none-any.whl",
            "sha256",
            bytes.fromhex("ab" * 32),
            separator="==",
            build_only=build_only,
        )


wheel = _Kit.wheel


class TestPip:
    @staticmethod
    def _plan(
        monkeypatch: pytest.MonkeyPatch,
        plan: InstallPlan,
        local: list[str] | None = None,
        editable: list[str] | None = None,
    ) -> list[Any]:
        requests: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            PipPlanner,
            "split_local",
            lambda args, cwd: (list(args), local or [], editable or []),
        )
        GuardKit.stub(
            monkeypatch,
            PipPlanner,
            "plan",
            lambda request, run, hooks, registries: requests.append(request) or plan,
        )
        return requests

    def test_registry_packages_are_installed_by_hash_from_the_scanned_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        plan = InstallPlan("pypi", [wheel("idna"), wheel("flit-core", build_only=True)])
        requests = self._plan(monkeypatch, plan)
        context = GuardKit.context(code=4)
        args = ["install", "--user", "-r", "req.txt", "-t", "dir", "idna"]
        assert PythonTools.pip("/bin/pip", args, context) == 4
        argv, _, _ = context.ran[0]
        assert argv[:5] == ["/bin/pip", "install", "--no-index", "--find-links", argv[4]]
        assert argv[5:8] == ["--require-hashes", "--no-deps", "-r"]
        assert argv[9:] == ["--user", "-t=dir"]
        assert context.requirements == f"idna==1.0 --hash=sha256:{'ab' * 32}\n"
        assert requests[0].args == args[1:]

    def test_an_install_that_has_nothing_to_do_says_so_and_runs_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi"))
        context = GuardKit.context()
        assert PythonTools.pip("pip", ["install", "idna"], context) == 0
        assert "nothing to install" in capsys.readouterr().err
        assert context.ran == []

    def test_a_blocked_package_installs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi", [wheel("evil")]))
        context = GuardKit.context(blocks=True)
        assert PythonTools.pip("pip", ["install", "evil"], context) == 1
        assert context.ran == []

    def test_local_and_editable_projects_are_built_one_by_one_after_the_pinned_install(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi", [wheel("idna")]), ["./a"], ["./b"])
        built: list[list[str]] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            built.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        context = GuardKit.context()
        assert (
            PythonTools.pip("/bin/pip", ["install", "--user", "idna", "./a", "-e", "./b"], context)
            == 0
        )
        assert len(context.ran) == 1, "the pinned registry install runs through the context"
        assert [b[-1] for b in built] == ["./a", "./b"]
        assert built[1][-2] == "-e"
        assert all("--no-deps" in b and "--user" in b and "--no-index" in b for b in built)

    def test_a_failed_pinned_install_stops_before_the_local_projects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi", [wheel("idna")]), ["./a"])
        context = GuardKit.context(code=9)
        assert PythonTools.pip("pip", ["install", "idna", "./a"], context) == 9

    def test_a_local_project_alone_is_built_and_its_failure_is_the_exit_code(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        plan = InstallPlan("pypi", local=[tmp_path / "a"])
        self._plan(monkeypatch, plan, ["./a"])
        monkeypatch.setattr(
            Subprocesses,
            "run",
            staticmethod(lambda argv, cwd, env: subprocess.CompletedProcess(argv, 2, "", "boom")),
        )
        assert PythonTools.pip("pip", ["install", "./a"], GuardKit.context()) == 2

    def test_pip_lines_that_install_and_the_options_pip_keeps(self) -> None:
        assert PythonTools.pip_installs(["install", "x"]) and not PythonTools.pip_installs(["list"])
        assert not PythonTools.pip_installs([])
        assert PythonTools.pip_keep(["--target=d", "--root", "/r", "-q", "--index-url", "u"]) == [
            "--target=d",
            "--root=/r",
            "-q",
        ]

    def test_which_uv_and_poetry_lines_install(self) -> None:
        assert PythonTools.uv_installs(["pip", "install", "x"])
        assert PythonTools.uv_installs(["pip", "sync", "r.txt"])
        assert not PythonTools.uv_installs(["pip", "list"])
        assert not PythonTools.uv_installs(["pip"])
        assert PythonTools.uv_installs(["tool", "install", "ruff"])
        assert PythonTools.uv_installs(["add", "x"]) and PythonTools.uv_installs(["sync"])
        assert not PythonTools.uv_installs(["venv"]) and not PythonTools.uv_installs([])
        assert PythonTools.poetry_installs(["add", "x"]) and PythonTools.poetry_installs(["sync"])
        assert not PythonTools.poetry_installs(["show"]) and not PythonTools.poetry_installs([])


class TestPoetry:
    @staticmethod
    def _plan(monkeypatch: pytest.MonkeyPatch, plan: InstallPlan) -> None:
        from cordon_scanner.sources.install.poetry import PoetryPlanner

        GuardKit.stub(
            monkeypatch, PoetryPlanner, "environment", lambda run, poetry, project: "/venv/python"
        )
        GuardKit.stub(
            monkeypatch,
            PoetryPlanner,
            "plan",
            lambda *a: SimpleNamespace(plan=plan, requirements="idna==1.0 --hash=sha256:ab\n"),
        )

    def test_a_clean_add_writes_the_lock_installs_by_hash_then_the_project_itself(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(
            monkeypatch, InstallPlan("pypi", [wheel("idna")], manifests={"poetry.lock": b"L"})
        )
        context = GuardKit.context()
        assert PythonTools.poetry("/bin/poetry", ["add", "idna"], context) == 0
        pip, root = (argv for argv, _, _ in context.ran)
        assert pip[:3] == ["/venv/python", "-m", "pip"] and "--require-hashes" in pip
        assert "--no-index" in pip and pip[-1].endswith("cordon-requirements.txt")
        assert context.requirements == "idna==1.0 --hash=sha256:ab\n"
        assert root == ["/bin/poetry", "install", "--only-root"]
        assert (tmp_path / "poetry.lock").read_bytes() == b"L"

    def test_a_verb_that_installs_no_project_and_a_failed_pip_stop_after_the_pip_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi"))
        context = GuardKit.context()
        assert PythonTools.poetry("poetry", ["remove", "idna"], context) == 0
        assert len(context.ran) == 1
        failing = GuardKit.context(code=3)
        assert PythonTools.poetry("poetry", ["add", "idna"], failing) == 3
        assert len(failing.ran) == 1

    def test_a_blocked_poetry_resolve_writes_nothing_and_runs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self._plan(monkeypatch, InstallPlan("pypi", manifests={"poetry.lock": b"L"}))
        context = GuardKit.context(blocks=True)
        assert PythonTools.poetry("poetry", ["add", "evil"], context) == 1
        assert context.ran == [] and not (tmp_path / "poetry.lock").exists()


class TestUvDispatch:
    def test_uv_resolves_with_the_projects_pip_and_hands_over_the_arguments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.python_env import TargetPython

        monkeypatch.chdir(tmp_path)
        GuardKit.stub(monkeypatch, TargetPython, "resolver", lambda run, cwd: ["/venv/bin/pip"])
        seen: list[Any] = []
        monkeypatch.setattr(
            UvInstall, "run", lambda self, args: seen.append((self.uv, args, self.hooks)) or 7
        )
        context = GuardKit.context()
        assert PythonTools.uv("/bin/uv", ["add", "x"], context) == 7
        assert seen[0][:2] == ("/bin/uv", ["add", "x"])

    def test_other_uv_verbs_run_unchanged(self) -> None:
        context = GuardKit.context(code=5)
        hooks = SimpleNamespace()
        assert UvInstall("/bin/uv", context, hooks).run(["venv", "--quiet"]) == 5  # type: ignore[arg-type]
        assert context.ran == [(["/bin/uv", "venv", "--quiet"], None, None)]


class TestUvPip:
    @staticmethod
    def _uv(
        monkeypatch: pytest.MonkeyPatch,
        plan: InstallPlan,
        local: list[str] | None = None,
        editable: list[str] | None = None,
        context: Any = None,
    ) -> tuple[UvInstall, list[Any]]:
        from cordon_scanner.sources.install.uv import UvPlanner

        asked: list[Any] = []
        planned = SimpleNamespace(
            plan=plan,
            target=SimpleNamespace(executable="/venv/bin/python"),
            requirements="",
            local=local or [],
            editable=editable or [],
        )
        GuardKit.stub(
            monkeypatch,
            UvPlanner,
            "pip_install",
            lambda args, run, uv, hooks, registries, cwd: asked.append(args) or planned,
        )
        hooks = SimpleNamespace(build_tools=lambda requires: [])
        return UvInstall("/bin/uv", context or GuardKit.context(), hooks), asked  # type: ignore[arg-type]

    def test_a_clean_pip_install_is_pinned_by_hash_and_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv, asked = self._uv(monkeypatch, InstallPlan("pypi", [wheel("idna")]))
        assert uv.run(["pip", "install", "idna"]) == 0
        argv = uv.context.ran[0][0]  # type: ignore[attr-defined]
        assert argv[:4] == ["/bin/uv", "pip", "install", "--no-index"]
        assert "--python" in argv and "/venv/bin/python" in argv
        assert argv[-4:-1] == ["--require-hashes", "--no-deps", "-r"]
        assert asked == [["idna"]]

    def test_a_pip_sync_reads_each_file_as_a_requirement_file_and_keeps_deps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv, asked = self._uv(monkeypatch, InstallPlan("pypi", [wheel("idna")]))
        assert uv.run(["pip", "sync", "a.txt", "--strict"]) == 0
        assert asked == [["-r", "a.txt", "--strict"]]
        argv = uv.context.ran[0][0]  # type: ignore[attr-defined]
        assert argv[2] == "sync" and "--no-deps" not in argv

    def test_a_blocked_pip_install_runs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv, _ = self._uv(
            monkeypatch, InstallPlan("pypi", [wheel("evil")]), context=GuardKit.context(blocks=True)
        )
        assert uv.run(["pip", "install", "evil"]) == 1
        assert uv.context.ran == []  # type: ignore[attr-defined]

    def test_local_and_editable_projects_are_built_after_the_registry_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        built: list[list[str]] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            built.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        uv, _ = self._uv(monkeypatch, InstallPlan("pypi"), ["/p/a"], ["/p/b"])
        assert uv.run(["pip", "install", "./a", "-e", "./b"]) == 0
        assert [b[-1] for b in built] == ["/p/a", "/p/b"]
        assert built[1][-2] == "-e" and built[0][:3] == ["/bin/uv", "pip", "install"]
        assert "--no-index" in built[0] and "--no-deps" in built[0]

    def test_a_failed_registry_install_skips_the_local_builds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        built: list[Any] = []
        monkeypatch.setattr(Subprocesses, "run", staticmethod(lambda a, c, e: built.append(a)))
        uv, _ = self._uv(
            monkeypatch,
            InstallPlan("pypi", [wheel("idna")]),
            ["/p/a"],
            context=GuardKit.context(code=6),
        )
        assert uv.run(["pip", "install", "idna", "./a"]) == 6
        assert built == []


class TestUvProject:
    @staticmethod
    def _uv(
        monkeypatch: pytest.MonkeyPatch,
        plan: InstallPlan,
        context: Any = None,
        tools: Any = None,
    ) -> UvInstall:
        from cordon_scanner.sources.install.uv import UvPlanner

        planned = SimpleNamespace(
            plan=plan, target=SimpleNamespace(executable="/venv/bin/python"), requirements=""
        )
        GuardKit.stub(monkeypatch, UvPlanner, "project", lambda *a: planned)
        hooks = SimpleNamespace(build_tools=tools or (lambda requires: []))
        return UvInstall("/bin/uv", context or GuardKit.context(), hooks)  # type: ignore[arg-type]

    @staticmethod
    def _argvs(uv: UvInstall) -> list[list[str]]:
        return [argv for argv, _, _ in uv.context.ran]  # type: ignore[attr-defined]

    def test_sync_makes_the_venv_installs_the_pinned_files_then_syncs_frozen(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        built: list[list[str]] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            built.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        uv = self._uv(
            monkeypatch, InstallPlan("pypi", [wheel("idna")], manifests={"uv.lock": b"L"})
        )
        assert uv.run(["sync", "--python", "3.12"]) == 0
        venv, deps = self._argvs(uv)
        assert venv == ["/bin/uv", "venv", "--quiet", "--python", "3.12"]
        assert (
            deps[:4] == ["/bin/uv", "pip", "install", "--no-index"] and "--require-hashes" in deps
        )
        assert built[0][:3] == ["/bin/uv", "sync", "--frozen"] and "--no-index" in built[0]
        assert (tmp_path / "uv.lock").read_bytes() == b"L"

    def test_run_executes_the_program_after_a_frozen_unsynced_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        monkeypatch.setattr(
            Subprocesses,
            "run",
            staticmethod(lambda a, c, e: subprocess.CompletedProcess(a, 0, "", "")),
        )
        uv = self._uv(monkeypatch, InstallPlan("pypi"))
        assert uv.run(["run", "--frozen", "--no-sync", "pytest", "-q"]) == 0
        assert self._argvs(uv) == [["/bin/uv", "run", "--frozen", "--no-sync", "pytest", "-q"]]

    def test_lock_writes_the_lock_after_a_clean_scan_and_installs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv = self._uv(monkeypatch, InstallPlan("pypi", manifests={"uv.lock": b"L"}))
        assert uv.run(["lock"]) == 0
        assert self._argvs(uv) == [], "no venv is made and nothing is installed for `uv lock`"
        assert (tmp_path / "uv.lock").read_bytes() == b"L"

    def test_a_blocked_project_resolve_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        uv = self._uv(
            monkeypatch,
            InstallPlan("pypi", manifests={"uv.lock": b"L"}),
            context=GuardKit.context(blocks=True),
        )
        assert uv.run(["add", "evil"]) == 1
        assert not (tmp_path / "uv.lock").exists() and self._argvs(uv) == []

    def test_a_failed_venv_stops_the_install(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv = self._uv(monkeypatch, InstallPlan("pypi"), context=GuardKit.context(code=2))
        assert uv.run(["add", "x"]) == 2
        assert len(self._argvs(uv)) == 1

    def test_a_failed_dependency_install_skips_the_sync_and_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        uv = self._uv(
            monkeypatch, InstallPlan("pypi", [wheel("idna")]), context=GuardKit.context(code=8)
        )
        assert uv.run(["run", "x"]) == 8
        assert len(self._argvs(uv)) == 1

    def test_a_packaged_project_has_its_build_tools_scanned_with_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling"]\n', encoding="utf-8"
        )
        asked: list[Any] = []
        tool = wheel("hatchling", build_only=True)
        uv = self._uv(
            monkeypatch,
            InstallPlan("pypi", [tool]),
            tools=lambda requires: asked.append(requires) or [tool, wheel("pathspec", True)],
        )
        monkeypatch.setattr(
            Subprocesses,
            "run",
            staticmethod(lambda a, c, e: subprocess.CompletedProcess(a, 0, "", "")),
        )
        assert uv.run(["sync"]) == 0
        assert asked == [("hatchling",)]
        plan = uv.context.checked[0]  # type: ignore[attr-defined]
        assert [f.name for f in plan.files] == ["hatchling", "pathspec"]

    def test_a_project_is_packaged_only_if_it_declares_a_build_system(self, tmp_path: Path) -> None:
        assert not UvInstall._packaged(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        assert not UvInstall._packaged(tmp_path)
        (tmp_path / "pyproject.toml").write_text("not = [toml", encoding="utf-8")
        assert not UvInstall._packaged(tmp_path)

    def test_the_python_option_and_the_program_arguments_are_split_out(self) -> None:
        assert UvInstall._python(["--python=3.12", "x"]) == ["--python", "3.12"]
        assert UvInstall._python(["x"]) == []
        assert UvInstall._program(["--frozen", "pytest", "--locked", "--no-sync", "-q"]) == [
            "pytest",
            "-q",
        ]
        assert UvInstall._requirements(InstallPlan("pypi", [wheel("a", True)]), Path("/")) == []


class TestUvTool:
    def test_a_tool_is_installed_from_the_scanned_files_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv, asked = TestUvPip._uv(monkeypatch, InstallPlan("pypi", [wheel("ruff")]))
        assert uv.run(["tool", "install", "ruff", "--python", "3.12"]) == 0
        argv = uv.context.ran[0][0]  # type: ignore[attr-defined]
        assert argv[:6] == ["/bin/uv", "tool", "install", "ruff", "--python", "3.12"]
        assert argv[6:8] == ["--no-index", "--find-links"]
        assert asked == [["ruff"]], "only the first requirement is planned"

    def test_a_blocked_tool_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        uv, _ = TestUvPip._uv(
            monkeypatch, InstallPlan("pypi", [wheel("evil")]), context=GuardKit.context(blocks=True)
        )
        assert uv.run(["tool", "install", "evil"]) == 1
        assert uv.context.ran == []  # type: ignore[attr-defined]


class SdistKit:
    @staticmethod
    def sdist(requires: str = '["setuptools"]') -> bytes:
        buffer = io.BytesIO()
        body = f"[build-system]\nrequires = {requires}\n".encode()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("pkg-1.0/pyproject.toml")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        return buffer.getvalue()

    @staticmethod
    def archive(filename: str, data: bytes, version: str = "1.0") -> SimpleNamespace:
        return SimpleNamespace(filename=filename, data=data, version=version)


class TestPythonHooks:
    @staticmethod
    def _hooks(context: Any = None) -> PythonHooks:
        return PythonHooks(["/venv/bin/python", "-m", "pip"], context or GuardKit.context())

    def test_the_hooks_are_the_three_callbacks_the_planner_asks_for(self) -> None:
        hooks = self._hooks()
        made = hooks.hooks()
        assert made.scan_sdist == hooks.scan_sdist
        assert made.scan_local == hooks.scan_local
        assert made.build_tools == hooks.build_tools

    def test_a_clean_sdist_passes_and_gives_its_version_and_build_requirements(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        GuardKit.stub(
            monkeypatch,
            ArchiveSources,
            "package_archive",
            lambda eco, name, version: SdistKit.archive("pkg-1.0.tar.gz", SdistKit.sdist()),
        )
        assert self._hooks().scan_sdist("pkg", "") == ("1.0", ("setuptools",))
        assert "its sdist was scanned and passed" in capsys.readouterr().err

    def test_a_blocked_sdist_is_never_built(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        GuardKit.stub(
            monkeypatch,
            ArchiveSources,
            "package_archive",
            lambda eco, name, version: SdistKit.archive("pkg-1.0.tar.gz", SdistKit.sdist()),
        )
        context = GuardKit.context()
        context.scan = lambda directory: ("finding",)  # type: ignore[assignment,method-assign]
        with pytest.raises(SdistBlocked) as blocked:
            self._hooks(context).scan_sdist("pkg", "1.0")
        assert blocked.value.label == "pkg==1.0" and blocked.value.findings == ("finding",)

    def test_an_sdist_that_cannot_be_fetched_or_is_only_a_wheel_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
        from cordon_scanner.intel.registries.registry_client import RegistryError

        def missing(eco: str, name: str, version: Any) -> Any:
            raise RegistryError("404")

        GuardKit.stub(monkeypatch, ArchiveSources, "package_archive", missing)
        with pytest.raises(InstallRefused, match="sdist could not be fetched: 404"):
            self._hooks().scan_sdist("pkg", "1.0")
        GuardKit.stub(
            monkeypatch,
            ArchiveSources,
            "package_archive",
            lambda eco, name, version: SdistKit.archive("pkg-1.0-py3-none-any.whl", b"", "1.0"),
        )
        with pytest.raises(InstallRefused, match="no wheel for this machine and no sdist"):
            self._hooks().scan_sdist("pkg", "1.0")

    def test_a_local_directory_is_scanned_where_it_is_and_an_archive_by_a_private_copy(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["flit_core"]\n', encoding="utf-8"
        )
        scanned: list[list[str]] = []
        context = GuardKit.context()
        context.scan = lambda d: scanned.append(sorted(p.name for p in d.iterdir())) or ()  # type: ignore[assignment,method-assign]
        assert self._hooks(context).scan_local(project) == ("flit_core",)
        archive = tmp_path / "pkg-1.0.tar.gz"
        archive.write_bytes(SdistKit.sdist('["hatchling"]'))
        assert self._hooks(context).scan_local(archive) == ("hatchling",)
        assert scanned == [["pyproject.toml"], ["pkg-1.0.tar.gz"]]
        assert "was scanned and passed" in capsys.readouterr().err

    def test_a_blocked_local_project_is_reported_by_its_path(self, tmp_path: Path) -> None:
        context = GuardKit.context()
        context.scan = lambda d: ("finding",)  # type: ignore[assignment,method-assign]
        with pytest.raises(SdistBlocked) as blocked:
            self._hooks(context).scan_local(tmp_path)
        assert blocked.value.label == f"the local project {tmp_path}"

    def test_build_tools_are_resolved_wheel_only_scanned_and_offered_to_the_build_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard
        from cordon_scanner.sources.install.plan import InstallVerdict

        assert self._hooks().build_tools(()) == []
        tool = wheel("hatchling", build_only=True)
        commands: list[list[str]] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            commands.append(list(argv))
            Path(argv[argv.index("--report") + 1]).write_text("{}", encoding="utf-8")
            assert env["PIP_NO_INPUT"] == "1"
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        GuardKit.stub(
            monkeypatch, PipPlanner, "files", lambda report, registries, build_only: [tool]
        )
        GuardKit.stub(
            monkeypatch,
            InstallGuard,
            "check",
            lambda plan, scan, fetch, scratch, cache: InstallVerdict(plan, {}),
        )
        assert self._hooks().build_tools(("hatchling",)) == [tool]
        assert "--only-binary=:all:" in commands[0] and commands[0][-1] == "hatchling"
        assert commands[0][:3] == ["/venv/bin/python", "-m", "pip"]

    def test_build_tools_that_will_not_resolve_or_are_blocked_stop_the_install(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard
        from cordon_scanner.sources.install.plan import InstallVerdict

        GuardKit.subprocess_says(monkeypatch, 1, "", "no matching distribution")
        with pytest.raises(InstallRefused, match="could not be resolved as wheels:\nno matching"):
            self._hooks().build_tools(("zzz",))

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            Path(argv[argv.index("--report") + 1]).write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        GuardKit.stub(monkeypatch, PipPlanner, "files", lambda report, registries, build_only: [])
        GuardKit.stub(
            monkeypatch,
            InstallGuard,
            "check",
            lambda plan, scan, fetch, scratch, cache: InstallVerdict(plan, {"x": ("f1", "f2")}),
        )
        with pytest.raises(SdistBlocked) as blocked:
            self._hooks().build_tools(("a", "b"))
        assert blocked.value.label == "the build tools a, b"
        assert blocked.value.findings == ("f1", "f2")


class TestBuildRetry:
    @staticmethod
    def _retry(tmp_path: Path, tools: Any, context: Any = None) -> BuildRetry:
        hooks = SimpleNamespace(build_tools=tools)
        return BuildRetry(hooks, context or GuardKit.context(), tmp_path)  # type: ignore[arg-type]

    @staticmethod
    def _runs(monkeypatch: pytest.MonkeyPatch, results: list[tuple[int, str, str]]) -> list[Any]:
        queue = iter(results)
        calls: list[Any] = []

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            code, out, err = next(queue)
            return subprocess.CompletedProcess(argv, code, out, err)

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        return calls

    def test_a_missing_build_tool_is_scanned_added_and_the_install_tried_again(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard

        calls = self._runs(
            monkeypatch,
            [(1, "", "No matching distribution found for editables>=0.5"), (0, "built\n", "")],
        )
        fetched: list[Any] = []
        GuardKit.stub(
            monkeypatch,
            InstallGuard,
            "fetch",
            lambda plan, into, fetch: fetched.append([f.name for f in plan.files]),
        )
        asked: list[Any] = []
        retry = self._retry(
            tmp_path, lambda requires: asked.append(requires) or [wheel("editables", True)]
        )
        assert retry.run(["pip", "install", "-e", "."]) == 0
        assert asked == [("editables>=0.5",)] and fetched == [["editables"]]
        assert len(calls) == 2
        assert capsys.readouterr().out == "built\n"

    def test_uvs_wording_of_a_missing_requirement_is_read_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard

        self._runs(
            monkeypatch,
            [(2, "", "because you require flit-core>=3, we can conclude"), (0, "", "")],
        )
        GuardKit.stub(monkeypatch, InstallGuard, "fetch", lambda *a: None)
        asked: list[Any] = []
        retry = self._retry(tmp_path, lambda r: asked.append(r) or [wheel("flit-core", True)])
        assert retry.run(["uv", "pip", "install", "."]) == 0
        assert asked == [("flit-core>=3",)]

    def test_a_failure_with_no_missing_tool_is_returned_and_its_error_shown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._runs(monkeypatch, [(3, "", "compile error")])
        context = GuardKit.context()
        retry = self._retry(tmp_path, lambda r: [], context)
        assert retry.run(["pip", "install", "."]) == 3
        assert "compile error" in GuardKit.said(context)

    def test_a_tool_already_in_the_directory_ends_the_retries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = wheel("editables", True)
        (tmp_path / tool.filename).write_bytes(b"")
        calls = self._runs(monkeypatch, [(1, "", "No matching distribution found for editables")])
        retry = self._retry(tmp_path, lambda r: [tool])
        assert retry.run(["pip", "install", "."]) == 1
        assert len(calls) == 1

    def test_the_retries_stop_after_the_rounds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.install.guard import InstallGuard

        failing = (1, "", "No matching distribution found for x")
        calls = self._runs(monkeypatch, [failing] * BuildRetry.ROUNDS)
        GuardKit.stub(monkeypatch, InstallGuard, "fetch", lambda *a: None)
        counter = iter(range(100))
        retry = self._retry(tmp_path, lambda r: [wheel(f"t{next(counter)}", True)])
        assert retry.run(["pip", "install", "."]) == 1
        assert len(calls) == BuildRetry.ROUNDS
