"""SI-V4: a scope fixture for each scope kind of the JavaScript resolver: module, function parameter, block (`let`/`const`), `var` hoisted to its
function, `catch` parameter, arrow parameter, loop binding, class method parameter, and a reference with no binding (the global). Each
fixture has the call that sees the inner binding and the call that sees the outer one, and says what each resolves to."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.front.resolve import CallResolver

CP = 'const cp = require("child_process");'


class Resolved:
    @staticmethod
    def names(source: str) -> list[str]:
        return sorted(c.name for c in CallResolver(typescript=False).resolve_calls(source))


class TestEachScopeKind:
    FIXTURES = (
        ("module", f"{CP} cp.exec(c);", ["child_process.exec", "require"]),
        (
            "function parameter",
            f"{CP} function f(cp) {{ cp.exec(c); }} cp.exec(d);",
            ["child_process.exec", "cp.exec", "require"],
        ),
        (
            "block",
            f"{CP} {{ const cp = x; cp.exec(1); }} cp.exec(2);",
            ["child_process.exec", "require", "x.exec"],
        ),
        (
            "var hoisted to its function",
            'function f() { if (a) { var cp = require("child_process"); } cp.exec(c); }',
            ["child_process.exec", "require"],
        ),
        (
            "catch parameter",
            f"{CP} try {{ a(); }} catch (cp) {{ cp.exec(c); }}",
            ["a", "cp.exec", "require"],
        ),
        ("arrow parameter", f"{CP} const g = (cp) => cp.exec(c);", ["cp.exec", "require"]),
        (
            "loop binding",
            f"{CP} for (const cp of list) {{ cp.exec(c); }} cp.exec(d);",
            ["child_process.exec", "cp.exec", "require"],
        ),
        (
            "class method parameter",
            f"{CP} class A {{ m(cp) {{ cp.exec(c); }} n() {{ cp.exec(d); }} }}",
            ["child_process.exec", "cp.exec", "require"],
        ),
        (
            "no binding: the global",
            "child_process.exec(c); eval(x);",
            ["child_process.exec", "eval"],
        ),
    )

    @pytest.mark.parametrize(
        ("scope", "source", "expected"), FIXTURES, ids=[f[0] for f in FIXTURES]
    )
    def test_each_call_resolves_to_the_binding_that_scope_gives_it(
        self, scope: str, source: str, expected: list[str]
    ) -> None:
        assert Resolved.names(source) == expected, scope

    def test_a_binding_in_one_function_is_not_seen_by_another(self) -> None:
        source = f"function a() {{ {CP} cp.exec(c); }} function b() {{ cp.exec(d); }}"
        assert Resolved.names(source) == ["child_process.exec", "cp.exec", "require"]

    def test_a_binding_of_the_same_name_in_two_functions_each_resolves_for_its_own(self) -> None:
        source = f"function a() {{ {CP} cp.exec(c); }} function b() {{ const cp = y; cp.exec(d); }}"
        assert Resolved.names(source) == ["child_process.exec", "require", "y.exec"]
