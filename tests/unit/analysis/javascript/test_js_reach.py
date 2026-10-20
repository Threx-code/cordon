"""Which JavaScript function bodies run when a file is loaded, and which wait for a call
(`JsFlow.deferred_spans`, review 98 `19-INTENT-ANALYSIS.md` step 2.1).

Wrapping code in a function must not make it look deferred: an immediately invoked function, a
callback, a function a running one calls by name, and the methods the language calls itself all
run on load.
"""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.js_flow import JsFlow


class TestReach:
    """Step 2.1: which function bodies run when the file is loaded, and which wait for a call."""

    CASES = (
        ("go();", False),
        ("module.exports = function () { go(); };", True),
        ("function f() { go(); }\nmodule.exports = f;", True),
        ("function f() { go(); }\nf();", False),
        ("(function () { go(); })();", False),
        ("!function () { go(); }();", False),
        ("(() => { go(); })();", False),
        ("setTimeout(() => { go(); }, 10);", False),
        ("function h() { go(); }\nprocess.on('exit', h);", False),
        ("function a() { b(); }\nfunction b() { go(); }\na();", False),
        ("function a() { b(); }\nfunction b() { go(); }\nexports.a = a;", True),
        ("module.exports = { run() { go(); } };", True),
        ("class X { constructor() { go(); } }\nnew X();", False),
        ("exports.f = () => { go(); };", True),
        ("exports.get = () => { go(); };", True),
        ("const o = { get x() { go(); } };\nmodule.exports = o;", False),
    )

    @pytest.mark.parametrize(("text", "deferred"), CASES)
    def test_a_body_is_deferred_only_when_nothing_loaded_reaches_it(self, text, deferred) -> None:
        spans = JsFlow.deferred_spans(text) or []
        at = text.index("go()")
        assert any(a <= at < b for a, b in spans) is deferred

    def test_a_file_past_the_limit_rules_nothing_out(self) -> None:
        assert JsFlow.deferred_spans("x" * 1_600_000) is None
