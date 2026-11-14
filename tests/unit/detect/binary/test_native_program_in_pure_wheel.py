"""A pure-Python wheel that carries a native program and starts it
(`ReleaseChecks.native_program_in_a_pure_wheel`).

Every wheel is assembled for the test: the "binaries" are a few magic bytes, nothing is run."""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

PURE = "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
PLATFORM = "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-manylinux_2_17_x86_64\n"
RUNNER = (
    "import os, stat, subprocess\n"
    "def run(*args):\n"
    "    exe = os.path.join(os.path.dirname(__file__), 'bin', 'tool')\n"
    "    os.chmod(exe, os.stat(exe).st_mode | stat.S_IEXEC)\n"
    "    return subprocess.run([exe, *args], env=os.environ.copy())\n"
)
RULE = "SUSPECT.BINARY.NATIVE_PROGRAM_IN_PURE_WHEEL.001"


class Kit:
    @staticmethod
    def rules(
        tmp_path: Path, members: dict[str, bytes | str], tag: str = "py3-none-any"
    ) -> set[str]:
        archive = tmp_path / f"demo-1.0-{tag}.whl"
        with zipfile.ZipFile(archive, "w") as z:
            for name, body in members.items():
                z.writestr(name, body)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}


class TestAPureWheelThatCarriesAProgram:
    def test_the_executable_and_the_run_block(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/bin/tool": b"\x7fELF" + bytes(60),
            "demo/__init__.py": RUNNER,
        }
        assert RULE in Kit.rules(tmp_path, members)

    def test_a_windows_executable(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/bin/tool": b"MZ\x90\x00" + bytes(60),
            "demo/__init__.py": RUNNER,
        }
        assert RULE in Kit.rules(tmp_path, members)


class TestOrdinaryWheels:
    def test_a_platform_wheel_that_wraps_its_binary_is_not(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PLATFORM,
            "demo/bin/tool": b"\x7fELF" + bytes(60),
            "demo/__init__.py": RUNNER,
        }
        assert RULE not in Kit.rules(tmp_path, members, "py3-none-manylinux_2_17_x86_64")

    def test_a_pure_wheel_with_an_extension_module_that_it_does_not_run_is_not(
        self, tmp_path: Path
    ) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/_speed.so": b"\x7fELF" + b"PyInit__speed" + bytes(40),
            "demo/__init__.py": "from . import _speed\n",
        }
        assert RULE not in Kit.rules(tmp_path, members)

    def test_a_pure_wheel_that_runs_the_users_program_is_not(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/data.bin": b"\x7fELF" + bytes(60),
            "demo/__init__.py": "import subprocess\ndef run(args):\n    return subprocess.run(['git', *args])\n",
        }
        assert RULE not in Kit.rules(tmp_path, members)


class TestASourceDistribution:
    @staticmethod
    def rules(tmp_path: Path, members: dict[str, bytes | str]) -> set[str]:
        import io
        import tarfile

        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, body in members.items():
                data = body if isinstance(body, bytes) else body.encode()
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    def test_a_prebuilt_program_run_from_the_sources_blocks(self, tmp_path: Path) -> None:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "setup.py": "from setuptools import setup\nsetup(name='demo')\n",
            "demo/bin/tool": b"\x7fELF" + bytes(60),
            "demo/__init__.py": RUNNER,
        }
        assert RULE in self.rules(tmp_path, members)

    def test_sources_with_a_fixture_binary_nothing_runs_is_not(self, tmp_path: Path) -> None:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "demo/data/sample.bin": b"\x7fELF" + bytes(60),
            "demo/__init__.py": "import subprocess\ndef run():\n    return subprocess.run(['git', 'status'])\n",
        }
        assert RULE not in self.rules(tmp_path, members)

    def test_sources_that_run_a_shipped_program_without_making_it_executable_are_not(
        self, tmp_path: Path
    ) -> None:
        runner = (
            "import os, subprocess\n"
            "def run(*args):\n"
            "    exe = os.path.join(os.path.dirname(__file__), 'bin', 'tool')\n"
            "    return subprocess.run([exe, *args])\n"
        )
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "demo/bin/tool": b"\x7fELF" + bytes(60),
            "demo/__init__.py": runner,
        }
        assert RULE not in self.rules(tmp_path, members)


class TestWhatTheCodeStarts:
    """The program the call starts is its first word. A shipped path handed to the interpreter as an
    argument is a script the interpreter runs, not a native program the package carries."""

    INTERPRETER = (
        "import os, subprocess, sys\n"
        "def run():\n"
        "    script = os.path.join(os.path.dirname(__file__), 'helper.py')\n"
        "    os.chmod(script, 0o755)\n"
        "    return subprocess.run([sys.executable, script])\n"
    )

    def test_a_shipped_script_run_by_the_interpreter_is_not(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/bin/tool": b"MZ\x90\x00" + bytes(60),
            "demo/__init__.py": self.INTERPRETER,
        }
        assert RULE not in Kit.rules(tmp_path, members)

    @pytest.mark.parametrize("launcher", ["'sh', '-c'", "'nohup'", "'sudo'", "'cmd', '/c'"])
    def test_a_shipped_program_started_through_another_program_still_is(
        self, tmp_path: Path, launcher: str
    ) -> None:
        """Only the running interpreter is exempt as the first word: a shell, `nohup` or `sudo`
        in front starts the program the package carries."""
        runner = (
            "import os, subprocess\n"
            "def run():\n"
            "    exe = os.path.join(os.path.dirname(__file__), 'bin', 'tool')\n"
            f"    return subprocess.Popen([{launcher}, exe])\n"
        )
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/bin/tool": b"MZ\x90\x00" + bytes(60),
            "demo/__init__.py": runner,
        }
        assert RULE in Kit.rules(tmp_path, members)

    def test_the_shipped_path_as_the_first_word_still_is(self, tmp_path: Path) -> None:
        members = {
            "demo-1.0.dist-info/WHEEL": PURE,
            "demo/bin/tool": b"MZ\x90\x00" + bytes(60),
            "demo/__init__.py": RUNNER,
        }
        assert RULE in Kit.rules(tmp_path, members)


class TestWhereTheSourcesRunIt:
    """A source distribution is installed by running its build files and by importing the package it
    builds. A file in a directory that is neither (a test, a release task, a vendored environment) is
    not run by anyone who installs it."""

    PKG = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
    EXE = b"MZ\x90\x00" + bytes(60)

    def rules(self, tmp_path: Path, members: dict[str, bytes | str]) -> set[str]:
        return TestASourceDistribution.rules(tmp_path, {"PKG-INFO": self.PKG, **members})

    def test_a_launcher_exercised_by_the_projects_tests_is_not(self, tmp_path: Path) -> None:
        members = {
            "demo/__init__.py": "",
            "demo/t32.exe": self.EXE,
            "tests/test_scripts.py": RUNNER,
        }
        assert RULE not in self.rules(tmp_path, members)

    def test_a_release_task_outside_the_package_is_not(self, tmp_path: Path) -> None:
        members = {"demo/__init__.py": "", "demo/t32.exe": self.EXE, "tasks/release.py": RUNNER}
        assert RULE not in self.rules(tmp_path, members)

    def test_a_vendored_environment_inside_the_sources_is_not(self, tmp_path: Path) -> None:
        deep = "venv/lib/python3.12/site-packages/lib/__init__.py"
        members = {"demo/__init__.py": "", "demo/t32.exe": self.EXE, deep: RUNNER}
        assert RULE not in self.rules(tmp_path, members)

    def test_the_setup_file_that_runs_it_still_is(self, tmp_path: Path) -> None:
        members = {"setup.py": RUNNER, "demo/__init__.py": "", "demo/bin/tool": self.EXE}
        assert RULE in self.rules(tmp_path, members)

    def test_the_package_in_a_src_layout_that_runs_it_still_is(self, tmp_path: Path) -> None:
        members = {"src/demo/__init__.py": RUNNER, "src/demo/bin/tool": self.EXE}
        assert RULE in self.rules(tmp_path, members)


class TestAFixtureWheelInsideSources:
    """A source distribution whose tests carry a wheel's metadata is still sources: only a
    `.dist-info/WHEEL` at the top of the archive says the archive is a wheel."""

    def test_a_wheel_fixture_does_not_make_the_sources_a_pure_wheel(self, tmp_path: Path) -> None:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "demo/__init__.py": "",
            "demo/t32.exe": b"MZ\x90\x00" + bytes(60),
            "tests/fixtures/old-1.0.dist-info/WHEEL": PURE,
            "tests/test_scripts.py": RUNNER,
        }
        assert RULE not in TestASourceDistribution.rules(tmp_path, members)
