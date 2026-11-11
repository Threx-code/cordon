"""A pure-Python wheel that carries a native program and starts it
(`ReleaseChecks.native_program_in_a_pure_wheel`).

Every wheel is assembled for the test: the "binaries" are a few magic bytes, nothing is run."""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

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
    def rules(tmp_path: Path, members: dict[str, bytes | str], tag: str = "py3-none-any") -> set[str]:
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

    def test_a_pure_wheel_with_an_extension_module_that_it_does_not_run_is_not(self, tmp_path: Path) -> None:
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

    def test_sources_that_run_a_shipped_program_without_making_it_executable_are_not(self, tmp_path: Path) -> None:
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
