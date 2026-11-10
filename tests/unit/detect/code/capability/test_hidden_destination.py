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
