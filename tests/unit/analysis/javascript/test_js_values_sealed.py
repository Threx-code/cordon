"""Whether an object's name is only read where it stands (`JsValues._only_read`) is decided from one pass over the file
for every name at once; the pass a name each made a bundle of thousands of names cost a pass each. The answer for each
name is the one the pass-per-name rule gave, kept here as the reference.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.analysis.javascript.js_flow import _Analysis
from cordon_scanner.analysis.javascript.js_values import JsValues, Key


class PassPerName:
    """The rule as it was first written: one pass over the file's tokens for each name asked about."""

    @staticmethod
    def only_read(values: JsValues, key: Key) -> bool:
        a, t = values.a, values.a.t
        for k in range(a.n):
            if not (a.is_name(k, key[1]) and a.resolve(key[1], a.scope_of(k)) == key):
                continue
            if (
                a.is_p(k - 1, ".")
                or a.is_p(k - 1, "?.")
                or (a.is_p(k + 1, ":") and a.is_p(k - 1, "{"))
            ):
                continue
            if a.is_p(k + 1, "=") and values._plain_target(k):
                continue
            if (a.is_p(k + 1, ".") or a.is_p(k + 1, "?.")) and a.is_name(k + 2):
                after = t[k + 3] if k + 3 < a.n else None
                if after is None or after.kind != "punct" or after.value not in values._WRITES:
                    continue
            elif (
                k + 1 < a.n
                and t[k + 1].kind == "punct"
                and t[k + 1].value in values._TESTED
                and not (a.is_p(k - 1, ",") or a.is_p(k - 1, "=") or a.is_name(k - 1, "return"))
                and not (a.is_p(k - 1, "(") and (a.is_name(k - 2) or a.is_p(k - 2, ")")))
            ):
                continue
            return False
        return True


class TestOneAnswerForEveryName:
    SOURCES: ClassVar[dict[str, str]] = {
        "read": "const o = { u: 'https://a.example.invalid/x' };\nfetch(o.u);\n",
        "passed": "const o = { u: 'https://a.example.invalid/x' };\nfn(o);\nfetch(o.u);\n",
        "aliased": "const o = { u: 'https://a.example.invalid/x' };\nconst p = o;\np.u = 'x';\nfetch(o.u);\n",
        "returned": "function g() { const o = { u: 'a' }; return o; }\nfetch(g().u);\n",
        "written": "const o = { u: 'https://a.example.invalid/x' };\no.u = other;\nfetch(o.u);\n",
        "called": "const o = { u: 'https://a.example.invalid/x' };\no.u();\nfetch(o.u);\n",
        "tested": "const o = { u: 'a' };\nif (o) { fetch(o.u); }\nif (!o) {}\nx = o && o.u;\n",
        "a key and a member": "const o = { o: 1 };\nconst q = { o: 2 };\nfetch(q.o + o.o);\n",
        "shadowed": "const o = { u: 'a' };\nfunction f(o) { return o; }\nfetch(o.u);\nf(1);\n",
        "spread": "const o = { u: 'a' };\nconst p = { ...o };\nfetch(p.u);\n",
        "two scopes": (
            "function a() { const o = { u: 'a' }; fetch(o.u); }\n"
            "function b() { const o = { u: 'b' }; use(o); }\n"
        ),
    }

    @pytest.mark.parametrize("name", sorted(SOURCES))
    def test_every_name_has_the_pass_per_name_answer(self, name: str) -> None:
        analysis = _Analysis(self.SOURCES[name])
        analysis.run()
        values = JsValues(analysis)
        keys = set(analysis.bound) | {
            analysis.resolve(str(token.value), analysis.scope_of(i))
            for i, token in enumerate(analysis.t)
            if token.kind == "name"
        }
        assert keys
        for key in keys:
            assert values._only_read(key) == PassPerName.only_read(values, key), key
