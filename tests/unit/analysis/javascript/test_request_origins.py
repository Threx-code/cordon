"""Where a request goes, read at the request site, as a fact of the file (note 70, V-a): the worker states how many
of a file's request sites name an external literal host, a loopback or private one, or a host nothing in the
file decides, and whether a decoded value reaches a process or an evaluator. The parent joins them across the
package (`CrossFileJoin.unexternal`); nothing here reads a file twice or invents a host.

Fixtures name hosts under `.invalid` or documentation and loopback addresses; nothing in them is run.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries
from cordon_scanner.analysis.javascript.js_flow import MAX_BYTES, JsFlow


class OriginKit:
    CLIENT: ClassVar[str] = "const http = require('http');\n"

    @staticmethod
    def classes(text: str) -> dict[str, int]:
        return {str(c): int(n) for c, n in JsFlow.summaries_raw(text)["js.request"]}

    @staticmethod
    def decoded(text: str) -> bool:
        return bool(JsFlow.summaries_raw(text)["js.decoded"])


class TestWhereARequestGoes:
    def test_an_external_literal_host(self) -> None:
        assert OriginKit.classes('fetch("https://updates.example.invalid/run.js");\n') == {
            "external": 1
        }

    def test_a_client_library_call(self) -> None:
        text = OriginKit.CLIENT + "http.get('https://updates.example.invalid/cmd', (res) => {});\n"
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_loopback_address(self) -> None:
        assert OriginKit.classes('fetch("http://127.0.0.1:8123/health");\n') == {"local": 1}

    def test_localhost_and_private_ranges_and_dot_local(self) -> None:
        for url in (
            "http://localhost:3000/x",
            "http://10.1.2.3/x",
            "http://192.168.1.5/x",
            "http://172.20.0.9/x",
            "http://printer.local/x",
        ):
            assert OriginKit.classes(f'fetch("{url}");\n') == {"local": 1}, url

    def test_a_parameter_decides_nothing(self) -> None:
        assert OriginKit.classes("function get(url) { return fetch(url); }\n") == {"unresolved": 1}

    def test_an_environment_variable_decides_nothing(self) -> None:
        assert OriginKit.classes("fetch(process.env.UPDATE_URL);\n") == {"unresolved": 1}

    def test_a_template_that_starts_with_an_external_host(self) -> None:
        assert OriginKit.classes("fetch(`https://api.example.invalid/v1/${id}`);\n") == {
            "external": 1
        }

    def test_a_template_that_starts_with_a_variable(self) -> None:
        assert OriginKit.classes("fetch(`${base}/v1/x`);\n") == {"unresolved": 1}

    def test_a_host_option(self) -> None:
        text = (
            OriginKit.CLIENT
            + "http.request({ host: 'api.example.invalid', path: '/x' }, (res) => {});\n"
        )
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_bound_literal(self) -> None:
        assert OriginKit.classes('const u = "https://x.example.invalid/a";\nfetch(u);\n') == {
            "external": 1
        }

    def test_each_site_counts_by_its_own_class(self) -> None:
        text = 'fetch("https://a.example.invalid/x");\nfetch("http://127.0.0.1/x");\nfetch(p);\n'
        assert OriginKit.classes(text) == {"external": 1, "local": 1, "unresolved": 1}

    def test_a_url_in_a_field_of_an_object_the_file_builds(self) -> None:
        text = (
            "function asset() {\n"
            "  const target = 'linux';\n"
            "  return { url: `https://updates.example.invalid/x-${target}.tgz` };\n"
            "}\n"
            "async function go() { const found = asset(); await fetch(found.url); }\n"
        )
        assert OriginKit.classes(text) == {"external": 1}

    def test_an_environment_variable_with_an_external_default_is_external(self) -> None:
        text = 'fetch((process.env.MIRROR || "https://updates.example.invalid/x") + "/f.tgz");\n'
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_raw_connection_to_an_external_literal_host(self) -> None:
        text = "const net = require('net');\nnet.connect(4444, 'updates.example.invalid');\n"
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_raw_connection_to_a_host_a_variable_decides(self) -> None:
        text = "const net = require('net');\nfunction c(h) { return net.connect(4444, h); }\n"
        assert OriginKit.classes(text) == {"unresolved": 1}

    def test_a_dns_lookup_of_an_external_literal_name(self) -> None:
        text = "const dns = require('dns');\ndns.resolveTxt('c2.example.invalid', () => {});\n"
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_url_with_credentials_names_the_host_after_them(self) -> None:
        assert OriginKit.classes('fetch("https://user:pw@updates.example.invalid/x");\n') == {
            "external": 1
        }

    def test_a_scheme_less_host_with_a_dot_or_localhost(self) -> None:
        assert OriginKit.classes('fetch("updates.example.invalid/x");\n') == {"external": 1}
        assert OriginKit.classes('fetch("localhost:3000/x");\n') == {"local": 1}

    def test_a_bare_word_or_a_relative_path_is_no_host(self) -> None:
        assert OriginKit.classes('fetch("update");\n') == {"unresolved": 1}
        assert OriginKit.classes('fetch("/api/v1/x");\n') == {"unresolved": 1}

    def test_a_helper_handed_an_external_literal_in_the_same_file(self) -> None:
        text = (
            "function get(url) { return fetch(url); }\n"
            'get("https://updates.example.invalid/cmd");\n'
        )
        assert OriginKit.classes(text) == {"external": 1, "unresolved": 1}

    def test_a_helper_handed_a_loopback_literal_stays_local_to_the_package(self) -> None:
        text = 'function get(url) { return fetch(url); }\nget("http://127.0.0.1:8123/cmd");\n'
        assert OriginKit.classes(text) == {"unresolved": 1}

    def test_a_helper_of_another_file_handed_an_external_literal(self) -> None:
        text = "const { go } = require('./lib/get');\ngo('https://updates.example.invalid/cmd');\n"
        assert OriginKit.classes(text) == {"external": 1}

    def test_an_external_url_given_to_a_logger_is_not_handed_on(self) -> None:
        assert OriginKit.classes('console.log("https://docs.example.invalid/help");\n') == {}

    def test_a_file_that_requests_nothing_states_nothing(self) -> None:
        assert OriginKit.classes("const a = 1 + 2;\nconsole.log(a);\n") == {}


class TestADecodedValueThatIsRun:
    def test_a_decoded_blob_reaching_an_evaluator(self) -> None:
        text = 'const c = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();\neval(c);\n'
        assert OriginKit.decoded(text)

    def test_a_decoded_blob_that_is_only_printed(self) -> None:
        text = (
            'const c = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();\nconsole.log(c);\n'
        )
        assert not OriginKit.decoded(text)

    def test_a_file_with_neither(self) -> None:
        assert not OriginKit.decoded("module.exports = 1;\n")


class TestAFileTheAnalysisCannotRead:
    def test_a_file_past_the_size_limit_says_so(self) -> None:
        text = "var a = 1;\n" * (MAX_BYTES // 8)
        assert len(text) > MAX_BYTES
        facts = JsFlow.summaries(text)
        assert facts["js.request"] == [["unread", 1]]

    def test_the_kinds_the_scan_sends(self) -> None:
        assert {"js.request", "js.decoded"} <= set(JsSummaries.KINDS)

    def test_a_file_that_joins_nothing_still_sends_its_requests(self) -> None:
        facts = JsFlow.summaries('fetch("https://a.example.invalid/x");\n')
        assert facts == {"js.request": [["external", 1]]}
