"""uv and poetry through Cordon (`sources/install/uv.py`, `poetry.py`, `python_env.py`): resolved with
building off, pinned by the lock's hashes, picked for the target interpreter by pip."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.sources.install.pip import PipHooks
from cordon_scanner.sources.install.plan import InstallRefused
from cordon_scanner.sources.install.poetry import PoetryPlanner
from cordon_scanner.sources.install.python_env import HashedRequirements, TargetPython
from cordon_scanner.sources.install.registries import InstallRegistries
from cordon_scanner.sources.install.uv import UvPlanner

PUBLIC = InstallRegistries()
HOOKS = PipHooks(lambda n, v: (v, ()), lambda p: (), lambda r: [])
REPORT = {
    "install": [
        {
            "metadata": {"name": "six", "version": "1.17.0"},
            "download_info": {
                "url": "https://files.pythonhosted.org/packages/s/six-1.17.0-py2.py3-none-any.whl",
                "archive_info": {"hashes": {"sha256": "4721f391" + "0" * 56}},
            },
        }
    ]
}
EXPORT = "six==1.17.0 \\\n    --hash=sha256:4721f391" + "0" * 56 + "\n"


class PyKit:
    @staticmethod
    def done(code: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, stdout, stderr)

    @staticmethod
    def tool(calls: list[list[str]], project: Path | None = None) -> Any:
        """uv, pip and a Python interpreter, as one stand-in runner."""

        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            argv = list(argv)
            calls.append(argv)
            if argv[1:3] == ["python", "find"]:
                return PyKit.done(stdout="/venv/bin/python\n")
            if argv[:2] == ["/venv/bin/python", "-I"]:
                return PyKit.done(stdout=json.dumps(["cpython", 3, 11, ""]))
            if argv[1:] == ["-m", "pip", "--version"]:
                return PyKit.done(stdout="pip 25")
            if "--report" in argv:
                Path(argv[argv.index("--report") + 1]).write_text(
                    json.dumps(REPORT), encoding="utf-8"
                )
                return PyKit.done()
            if argv[1:3] == ["pip", "compile"]:
                return PyKit.done(stdout=EXPORT + "-e file:///work/local\n    # via -r in\n")
            if argv[1] == "export":
                return PyKit.done(stdout=EXPORT)
            if project is not None:
                assert cwd != project, "uv resolves in a private copy, never the project"
            if argv[1] in {"add", "lock"}:
                (cwd / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            return PyKit.done()

        return run


class TestTheTargetInterpreter:
    def test_pip_is_told_the_targets_version_and_abi(self, tmp_path: Path) -> None:
        target = TargetPython.of("/venv/bin/python", PyKit.tool([]), tmp_path)
        assert target.flags() == [
            "--python-version", "3.11", "--implementation", "cp",
            "--abi", "cp311", "--abi", "abi3", "--abi", "none",
        ]  # fmt: skip

    def test_an_interpreter_that_will_not_say_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="which Python"):
            TargetPython.of("/x/python", lambda *a: PyKit.done(stdout="nonsense"), tmp_path)


class TestUv:
    def test_uv_pip_install_compiles_without_building_then_pip_picks_the_file(
        self, tmp_path: Path
    ) -> None:
        calls: list[list[str]] = []
        planned = UvPlanner.pip_install(["six"], PyKit.tool(calls), "uv", HOOKS, PUBLIC, tmp_path)
        compile_ = next(c for c in calls if c[1:3] == ["pip", "compile"])
        assert "--no-build" in compile_ and "--generate-hashes" in compile_
        resolve = next(c for c in calls if "--report" in c)
        assert "--python-version" in resolve and "--no-deps" in resolve
        assert [f.label for f in planned.plan.files] == ["six==1.17.0"]
        assert "file://" not in planned.requirements, "local entries are built from disk later"

    def test_uv_add_locks_privately_with_building_off(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "0"\n', encoding="utf-8"
        )
        calls: list[list[str]] = []
        planned = UvPlanner.project(
            "add", ["six"], PyKit.tool(calls, tmp_path), "uv", HOOKS, PUBLIC, tmp_path
        )
        add = next(c for c in calls if c[1] == "add")
        assert "--no-sync" in add and "--no-build" in add
        assert "uv.lock" in planned.plan.manifests and not (tmp_path / "uv.lock").exists()

    def test_frozen_skips_the_lock(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "0"\n', encoding="utf-8"
        )
        calls: list[list[str]] = []
        UvPlanner.project("sync", ["--frozen"], PyKit.tool(calls), "uv", HOOKS, PUBLIC, tmp_path)
        assert not any(c[1] == "lock" for c in calls)

    def test_a_package_that_needs_a_build_is_refused_with_its_name(self, tmp_path: Path) -> None:
        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            if list(argv)[1:3] == ["python", "find"]:
                return PyKit.done(stdout="/venv/bin/python\n")
            if list(argv)[:2] == ["/venv/bin/python", "-I"]:
                return PyKit.done(stdout=json.dumps(["cpython", 3, 11, ""]))
            return PyKit.done(
                1, stderr="Wheels are required for `docopt` because building ... `--no-build`"
            )

        with pytest.raises(InstallRefused, match=r"pip install. in the environment"):
            UvPlanner.pip_install(["docopt"], run, "uv", HOOKS, PUBLIC, tmp_path)

    def test_only_the_selection_options_reach_the_export(self) -> None:
        assert UvPlanner._export_flags(["--extra", "web", "--no-dev", "--python", "3.12"]) == [
            "--extra=web",
            "--no-dev",
        ]


class TestPoetry:
    LOCK = """
[[package]]
name = "six"
version = "1.17.0"
files = [
    {file = "six-1.17.0-py2.py3-none-any.whl", hash = "sha256:aa"},
    {file = "six-1.17.0.tar.gz", hash = "sha256:bb"},
]

[[package]]
name = "colorama"
version = "0.4.6"
markers = "sys_platform == \\"win32\\""
files = [{file = "colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:cc"}]

[[package]]
name = "mine"
version = "0.1.0"
files = []
[package.source]
type = "directory"
url = "../mine"
"""

    def test_the_lock_becomes_hashed_requirements_with_its_markers(self) -> None:
        lines = HashedRequirements.from_poetry(self.LOCK).splitlines()
        assert lines == [
            "six==1.17.0 --hash=sha256:aa --hash=sha256:bb",
            'colorama==0.4.6 ; sys_platform == "win32" --hash=sha256:cc',
        ]

    def test_a_git_dependency_is_refused(self) -> None:
        text = '[[package]]\nname = "x"\nversion = "1"\n[package.source]\ntype = "git"\nurl = "https://x/r.git"\n'
        with pytest.raises(InstallRefused, match="not a registry"):
            HashedRequirements.from_poetry(text)

    def test_a_poetry_spec_reads_as_pip(self) -> None:
        assert PoetryPlanner.as_pip("requests@2.32.3") == "requests==2.32.3"
        assert PoetryPlanner.as_pip("requests@^2.0") == "requests"
        assert PoetryPlanner.as_pip("requests") == "requests"

    def test_an_added_package_with_no_wheel_is_refused_before_poetry_locks(
        self, tmp_path: Path
    ) -> None:
        def run(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            if list(argv)[:2] == ["/venv/bin/python", "-I"]:
                return PyKit.done(stdout=json.dumps(["cpython", 3, 11, ""]))
            if list(argv)[1:] == ["-m", "pip", "--version"]:
                return PyKit.done(stdout="pip")
            return PyKit.done(1, stderr="No matching distribution found for docopt")

        with pytest.raises(InstallRefused, match="docopt has no wheel"):
            PoetryPlanner._precheck(["docopt"], run, HOOKS, PUBLIC, tmp_path, "/venv/bin/python")
