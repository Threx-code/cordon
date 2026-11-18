"""Where a request goes, read at the request site, as a fact of the file: the worker states how many
of a file's request sites name an external literal host, a loopback or private one, or a host nothing in the
file decides, and whether a decoded value reaches a process or an evaluator. The parent joins them across the
package (`CrossFileJoin.unexternal`); nothing here reads a file twice or invents a host.

Fixtures name hosts under `.invalid` or documentation and loopback addresses; nothing in them is run.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.analysis.javascript.flow.origins import RequestOrigins
from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries
from cordon_scanner.analysis.javascript.js_flow import MAX_BYTES, JsFlow, _Analysis
from cordon_scanner.engine.isolation.facts import JsShapes


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

    def test_a_url_split_across_literals_is_still_handed_on(self) -> None:
        """No literal holds `://`: the scheme and the host are two strings joined where the helper is called."""
        text = (
            "function get(url) { return fetch(url); }\n"
            'get("https:" + "//updates.example.invalid/cmd");\n'
        )
        assert OriginKit.classes(text) == {"external": 1, "unresolved": 1}

    def test_a_url_split_by_a_bound_scheme_is_still_handed_on(self) -> None:
        text = (
            "function get(url) { return fetch(url); }\n"
            "const scheme = 'https:';\n"
            "const host = '//updates.example.invalid/cmd';\n"
            "get(scheme + host);\n"
        )
        assert OriginKit.classes(text) == {"external": 1, "unresolved": 1}

    def test_a_url_split_across_literals_handed_to_a_helper_of_another_file(self) -> None:
        text = (
            "const { go } = require('./lib/get');\n"
            "go('https:' + '//updates.example.invalid/cmd');\n"
        )
        assert OriginKit.classes(text) == {"external": 1}

    def test_a_split_loopback_url_stays_local_to_the_package(self) -> None:
        text = 'function get(url) { return fetch(url); }\nget("http:" + "//127.0.0.1:8123/cmd");\n'
        assert OriginKit.classes(text) == {"unresolved": 1}

    def test_strings_that_name_no_host_are_not_handed_on(self) -> None:
        text = "function get(url) { return fetch(url); }\nget('a' + 'b');\n"
        assert OriginKit.classes(text) == {"unresolved": 1}

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


class StepKit:
    """A file of `count` helpers, each handed a field of an object the file builds: the shape of a bundle."""

    @staticmethod
    def bundle(count: int) -> str:
        return "".join(
            f"function f{i}(a) {{ return a; }}\n"
            f"const o{i} = {{ u: 'https://h{i}.example.invalid/x' }};\n"
            f"f{i}(o{i}.u);\n"
            for i in range(count)
        )

    @staticmethod
    def diamond(levels: int) -> str:
        """Each name is three of the one before: a name reached by 3**levels paths, read once."""
        lines = ["const a0 = 'https://h.example.invalid/';"]
        lines += [f"const a{i} = a{i - 1} + a{i - 1} + a{i - 1};" for i in range(1, levels + 1)]
        return "\n".join(lines) + f"\nfunction f(u) {{ return u; }}\nf(a{levels});\n"

    @staticmethod
    def analysed(text: str) -> _Analysis:
        analysis = _Analysis(text)
        analysis.run()
        return analysis


class TestTheStepBudget:
    """What a file's origins cost is counted in steps, never in time, and past the limit the file is `over_budget`:
    nothing is known of where it requests, so the package keeps its block (an unknown is never read as "no external
    host")."""

    SITE: ClassVar[str] = 'fetch("https://updates.example.invalid/x");\n'

    @pytest.fixture
    def no_steps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(RequestOrigins, "STEP_FLOOR", 0)
        monkeypatch.setattr(RequestOrigins, "STEPS_PER_TOKEN", 0)

    def test_a_file_within_the_budget_is_read_as_before(self) -> None:
        assert OriginKit.classes(self.SITE) == {"external": 1}

    def test_a_file_past_the_budget_says_over_budget(self, no_steps: None) -> None:
        assert OriginKit.classes(self.SITE) == {"over_budget": 1}

    def test_over_budget_is_a_class_the_channel_accepts(self) -> None:
        assert "over_budget" in JsShapes.REQUEST_CLASSES
        assert JsShapes.request(["over_budget", 1])

    def test_a_file_that_requests_nothing_spends_nothing(self, no_steps: None) -> None:
        assert OriginKit.classes("module.exports = 1;\n") == {}

    def test_an_analysis_that_did_not_reach_every_call_says_over_budget(self) -> None:
        analysis = StepKit.analysed(self.SITE)
        assert analysis.sites_complete
        analysis.sites_complete = False
        assert RequestOrigins.classes(analysis) == {"over_budget": 1}

    def test_the_sites_are_the_analysis_own_not_a_second_walk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysis = StepKit.analysed(
            self.SITE + "const http = require('http');\nhttp.get('http://127.0.0.1/x');\n"
        )

        def refuse(*_args: object) -> None:
            raise AssertionError("a second sink walk")

        monkeypatch.setattr(analysis, "_sink_kind", refuse)
        assert RequestOrigins.classes(analysis) == {"external": 1, "local": 1}

    def test_the_steps_spent_are_reported(self) -> None:
        classes, steps = RequestOrigins.measure(StepKit.analysed(self.SITE))
        assert classes == {"external": 1}
        assert steps > 0

    def test_the_limit_is_in_steps_not_time(self) -> None:
        import inspect

        from cordon_scanner.analysis.javascript.flow import origins

        source = inspect.getsource(origins)
        assert "perf_counter" not in source
        assert "monotonic" not in source
        assert "process_time" not in source
        assert "time.time" not in source

    def test_the_work_grows_with_the_file_not_with_its_names(self) -> None:
        """A name per helper must not cost a pass over the whole file each: doubling the file at most doubles
        the steps (a bundle of thousands of helpers is the heavy case)."""
        small = RequestOrigins.measure(StepKit.analysed(StepKit.bundle(150)))[1]
        large = RequestOrigins.measure(StepKit.analysed(StepKit.bundle(300)))[1]
        assert large <= 2.5 * small

    def test_a_name_reached_by_many_paths_is_read_once(self) -> None:
        """3**7 paths lead to the first name; reading each path again cost thousands of steps for one call."""
        classes, steps = RequestOrigins.measure(StepKit.analysed(StepKit.diamond(7)))
        assert classes == {"external": 1}
        assert steps <= 500

    def test_a_default_searched_through_many_paths_is_read_once(self) -> None:
        """A request whose address nothing decides sends the search through every name in its argument, and each
        name through everything it is bound to: thirty names that each lead to thirty more are 27,000 reads when
        every path is walked and about a hundred when each range is read once."""
        text = (
            "const l3 = 'plain';\n"
            f"const l2 = [{', '.join(['l3'] * 30)}];\n"
            f"const l1 = [{', '.join(['l2'] * 30)}];\n"
            f"const l0 = [{', '.join(['l1'] * 30)}];\n"
            "fetch(l0);\n"
        )
        classes, steps = RequestOrigins.measure(StepKit.analysed(text))
        assert classes == {"unresolved": 1}
        assert steps <= 2_000

    def test_a_bundle_stays_inside_the_default_budget(self) -> None:
        analysis = StepKit.analysed(StepKit.bundle(300))
        classes, steps = RequestOrigins.measure(analysis)
        assert "over_budget" not in classes
        assert steps <= RequestOrigins.STEP_FLOOR + RequestOrigins.STEPS_PER_TOKEN * analysis.n
