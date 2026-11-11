"""A program started and left running when a package is imported (`flows/implants/import_starts.py`).

Every source is assembled for the test and only parsed."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path


class Kit:
    @staticmethod
    def started(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "program started at import"]


class TestAProgramLeftRunning:
    def test_a_literal_program_started_with_popen_at_module_level(self) -> None:
        source = "import subprocess\nsubprocess.Popen(['helper-tool', '--serve'])\n"
        assert Kit.started(source) == ["program started at import"]

    def test_through_a_helper_the_module_level_calls(self) -> None:
        source = (
            "import subprocess\n"
            "def _boot():\n"
            "    subprocess.Popen(['helper-tool'])\n"
            "_boot()\n"
        )
        assert Kit.started(source) == ["program started at import"]


class TestOrdinaryImports:
    def test_a_probe_that_reads_the_answer(self) -> None:
        source = "import subprocess\nout = subprocess.check_output(['gdal-config', '--version'])\n"
        assert Kit.started(source) == []

    def test_a_handle_that_is_kept_still_leaves_it_running(self) -> None:
        source = "import subprocess\nproc = subprocess.Popen(['helper-tool'])\nwhile True:\n    pass\n"
        assert Kit.started(source) == ["program started at import"]

    def test_a_launcher_that_pipes_the_output_and_loops_over_it(self) -> None:
        source = (
            "import subprocess\n"
            "proc = subprocess.Popen(['helper-tool'], stdout=subprocess.PIPE, universal_newlines=True)\n"
            "while True:\n"
            "    line = proc.stdout.readline()\n"
        )
        assert Kit.started(source) == ["program started at import"]

    def test_the_permission_tools(self) -> None:
        source = "import subprocess\nsubprocess.Popen(['chmod', '+x', 'run.sh'])\nsubprocess.Popen(['sudo', 'true'])\n"
        assert Kit.started(source) == []

    def test_the_terminal_the_interpreter_and_git(self) -> None:
        source = (
            "import subprocess, sys\n"
            "subprocess.Popen(['clear'])\n"
            "subprocess.Popen([sys.executable, '-m', 'x'])\n"
            "subprocess.Popen(['git', 'status'])\n"
        )
        assert Kit.started(source) == []

    def test_in_a_function_nothing_calls(self) -> None:
        source = "import subprocess\ndef launch():\n    subprocess.Popen(['helper-tool'])\n"
        assert Kit.started(source) == []


class TestTheRule:
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

    def test_an_init_that_starts_a_program_blocks(self, tmp_path: Path) -> None:
        init = "import subprocess\nsubprocess.Popen(['helper-tool', '--serve'])\n"
        assert "MALWARE.IMPORT.PROGRAM_START.001" in self.rules(tmp_path, init)
