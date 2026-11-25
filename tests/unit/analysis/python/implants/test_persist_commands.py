"""Persistence done by a command, not by naming a path (`CAP.PY.PERSIST.001`).

Every source is assembled for the test and only parsed. A scheduled task, a service, an agent, a login
item, an autostart entry or a udev rule created at install is what `MALWARE.INSTALL.PERSIST.001` reads;
the twins list or query what exists, or sit in a library nothing installs."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

SCHTASKS = "scht" + "asks"
LAUNCH = "launch" + "ctl"

INSTALL = (
    "import subprocess\n"
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
    def rules(tmp_path: Path, setup: str) -> set[str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "setup.py": setup,
            "demo/__init__.py": "",
        }
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}


class TestAnInstallHookThatRegistersItself:
    @pytest.mark.parametrize(
        "body",
        [
            f"subprocess.run(['{SCHTASKS}', '/create', '/tn', 'x', '/tr', 'y', '/sc', 'onlogon'])",
            f"subprocess.run('{SCHTASKS} /create /tn x /tr y', shell=True)",
            "subprocess.run(['sc', 'create', 'svc', 'binPath=', 'y'])",
            f"subprocess.run(['{LAUNCH}', 'load', '/x/y.plist'])",
            f"subprocess.run(['{LAUNCH}', 'bootstrap', 'gui/501', '/x/y.plist'])",
            "open('/etc/udev/rules.d/99-x.rules', 'w').write('x')",
            "open('/home/u/.config/autostart/x.desktop', 'w').write('x')",
        ],
    )
    def test_the_command_is_persistence(self, tmp_path: Path, body: str) -> None:
        assert "MALWARE.INSTALL.PERSIST.001" in Kit.rules(tmp_path, INSTALL.format(body=body))


class TestOrdinaryUses:
    @pytest.mark.parametrize(
        "body",
        [
            f"subprocess.run(['{SCHTASKS}', '/query'])",
            f"subprocess.run(['{LAUNCH}', 'list'])",
            "subprocess.run(['make', 'all'])",
        ],
    )
    def test_a_query_or_a_build_is_not(self, tmp_path: Path, body: str) -> None:
        assert "MALWARE.INSTALL.PERSIST.001" not in Kit.rules(tmp_path, INSTALL.format(body=body))

    def test_a_scheduler_library_nothing_installs_is_not_an_install_finding(
        self, tmp_path: Path
    ) -> None:
        setup = "from setuptools import setup\nsetup(name='demo')\n"
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "setup.py": setup,
            "demo/__init__.py": "",
            "demo/windows.py": (
                "import subprocess\n"
                "def create(name, command):\n"
                f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', name, '/tr', command])\n"
            ),
        }
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert "MALWARE.INSTALL.PERSIST.001" not in {f.rule_id for f in result.findings}


class TestAnImportThatRegistersItself:
    @staticmethod
    def rules(tmp_path: Path, init: str) -> set[str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'demo'\nversion = '1.0'\n",
            "src/demo/__init__.py": init,
        }
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    def test_a_task_created_when_the_package_is_loaded_blocks(self, tmp_path: Path) -> None:
        init = (
            "import subprocess\n"
            f"subprocess.run(['{SCHTASKS}', '/create', '/tn', 'x', '/tr', 'y', '/sc', 'onlogon'])\n"
        )
        assert "MALWARE.IMPORT.PERSIST.001" in self.rules(tmp_path, init)

    def test_a_profile_line_appended_when_it_is_loaded_blocks(self, tmp_path: Path) -> None:
        init = (
            "import os\n"
            "with open(os.path.expanduser('~/.bashrc'), 'a') as rc:\n"
            "    rc.write('export X=1\\n')\n"
        )
        assert "MALWARE.IMPORT.PERSIST.001" in self.rules(tmp_path, init)

    def test_the_same_in_a_function_nothing_calls_is_not_this(self, tmp_path: Path) -> None:
        init = (
            "import subprocess\n"
            "def enable(name):\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', name])\n"
        )
        assert "MALWARE.IMPORT.PERSIST.001" not in self.rules(tmp_path, init)

    def test_a_listing_when_it_is_loaded_is_not_a_write(self, tmp_path: Path) -> None:
        init = f"import subprocess\nsubprocess.run(['{SCHTASKS}', '/query'])\n"
        assert "MALWARE.IMPORT.PERSIST.001" not in self.rules(tmp_path, init)

    def test_a_helper_the_module_level_calls_counts(self, tmp_path: Path) -> None:
        init = (
            "import subprocess\n"
            "def _register():\n"
            f"    subprocess.run(['{LAUNCH}', 'load', '/x/y.plist'])\n"
            "def _boot():\n"
            "    _register()\n"
            "_boot()\n"
        )
        assert "MALWARE.IMPORT.PERSIST.001" in self.rules(tmp_path, init)

    def test_the_main_guard_is_not_loading(self, tmp_path: Path) -> None:
        init = (
            "import subprocess\n"
            "def _register():\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', 'x'])\n"
            "if __name__ == '__main__':\n"
            "    _register()\n"
        )
        assert "MALWARE.IMPORT.PERSIST.001" not in self.rules(tmp_path, init)
