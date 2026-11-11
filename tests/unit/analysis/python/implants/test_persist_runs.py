"""A persistence write beside the run of a program the package brings (`flows/persist_runs.py`).

Every source is assembled for the test and only parsed. The twins have one of the two, or both far
apart in unrelated functions."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer

SCHTASKS = "scht" + "asks"


class Kit:
    @staticmethod
    def facts(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail in ("persist and run", "shipped program run")
        ]


class TestARunOfShippedProgram:
    def test_a_path_built_from_the_file(self) -> None:
        source = (
            "import os, subprocess\n"
            "def go():\n"
            "    exe = os.path.join(os.path.dirname(__file__), 'bin', 'tool')\n"
            "    subprocess.run([exe, '--version'])\n"
        )
        assert Kit.facts(source) == ["shipped program run"]

    def test_a_resource_path(self) -> None:
        source = (
            "import subprocess\n"
            "from importlib import resources\n"
            "def go():\n"
            "    exe = resources.files('demo') / 'tool'\n"
            "    subprocess.run([str(exe)])\n"
        )
        assert Kit.facts(source) == ["shipped program run"]

    def test_a_system_program_is_not(self) -> None:
        source = "import subprocess\nsubprocess.run(['git', 'status'])\n"
        assert Kit.facts(source) == []


class TestPersistenceBesideARun:
    def test_a_task_registered_for_a_downloaded_program(self) -> None:
        source = (
            "import subprocess, urllib.request\n"
            "def install(url, exe):\n"
            "    urllib.request.urlretrieve(url, exe)\n"
            "    subprocess.run([exe])\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', 'agent', '/tr', exe])\n"
        )
        assert "persist and run" in Kit.facts(source)

    def test_a_task_for_a_program_the_package_ships_is_not(self) -> None:
        source = (
            "import os, subprocess\n"
            "def install():\n"
            "    exe = os.path.join(os.path.dirname(__file__), 'agent.exe')\n"
            "    subprocess.run([exe])\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', 'agent', '/tr', exe])\n"
        )
        assert "persist and run" not in Kit.facts(source)

    def test_the_run_in_a_helper_the_function_calls(self) -> None:
        source = (
            "import os, subprocess, urllib.request\n"
            "def start(url, exe):\n"
            "    urllib.request.urlretrieve(url, exe)\n"
            "    subprocess.run([exe])\n"
            "def register():\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', 'agent'])\n"
            "def install():\n"
            "    start('u', 'e')\n"
            "    register()\n"
        )
        assert "persist and run" in Kit.facts(source)

    def test_a_scheduler_with_no_run_is_not(self) -> None:
        source = (
            "import subprocess\n"
            "def enable(name, command):\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', name, '/tr', command])\n"
        )
        assert Kit.facts(source) == []

    def test_a_run_and_a_scheduler_in_unrelated_functions_is_not(self) -> None:
        source = (
            "import os, subprocess\n"
            "def convert(path):\n"
            "    subprocess.run([os.path.join(os.path.dirname(__file__), 'convert'), path])\n"
            "def schedule(name):\n"
            f"    subprocess.run(['{SCHTASKS}', '/create', '/tn', name])\n"
        )
        assert "persist and run" not in Kit.facts(source)




class TestAutostartThatHides:
    @staticmethod
    def hidden(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "autostart hidden"]

    def test_a_desktop_entry_and_a_launcher_run_with_no_window(self) -> None:
        source = (
            "import os, subprocess\n"
            "def install_registry_entry():\n"
            "    path = os.path.join(os.path.expanduser('~'), '.config/autostart', 'x.desktop')\n"
            "    open(path, 'w').write('[Desktop Entry]')\n"
            "    subprocess.Popen(['wscript', 'launch.vbs'], creationflags=subprocess.CREATE_NO_WINDOW)\n"
        )
        assert "autostart hidden" in self.hidden(source)

    def test_the_flags_in_a_helper(self) -> None:
        source = (
            "import os, subprocess\n"
            "def _flags():\n"
            "    return subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS\n"
            "def install():\n"
            "    open(os.path.expanduser('~/.config/autostart/x.desktop'), 'w').write('x')\n"
            "    subprocess.Popen(['app'], creationflags=_flags())\n"
        )
        assert "autostart hidden" in self.hidden(source)

    def test_an_autostart_with_a_visible_program_is_not(self) -> None:
        source = (
            "import os, subprocess\n"
            "def install():\n"
            "    open(os.path.expanduser('~/.config/autostart/x.desktop'), 'w').write('x')\n"
            "    subprocess.Popen(['app', '--show'])\n"
        )
        assert self.hidden(source) == []

    def test_a_hidden_launch_with_no_persistence_is_not(self) -> None:
        source = "import subprocess\nsubprocess.Popen(['tool'], creationflags=subprocess.CREATE_NO_WINDOW)\n"
        assert self.hidden(source) == []
