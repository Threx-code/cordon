"""The syntax tree of a JavaScript or TypeScript source, from Cordon's own parser."""

from __future__ import annotations

import random
import time

import pytest

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax


class Parsed:
    @staticmethod
    def errors(text: str, *, typescript: bool = False, jsx: bool = True) -> int:
        parser = Parser(text, typescript=typescript, jsx=jsx)
        parser.program()
        return parser.errors

    @staticmethod
    def types(text: str, *, typescript: bool = False) -> list[str]:
        program = Parser(text, typescript=typescript, jsx=not typescript).program()
        return [n.type for n in Syntax.walk(program)]


class TestEcmaScript:
    @pytest.mark.parametrize(
        "source",
        [
            "var a = 1, b; let c; const d = 2;",
            "function f(a, b = 1, ...c) { return a; }",
            "async function* g() { yield* h(); await x; for await (const y of z) {} }",
            "class A extends B { #p = 1; static s; get x() { return this.#p; } static { init(); } }",
            "const { a, b: { c }, ...rest } = o; const [x, , y = 2, ...zs] = arr;",
            "a?.b?.[c]?.(d) ?? e; x ||= y; x &&= y; x ??= y; 2 ** 3;",
            "label: for (let i = 0; i < n; i++) { if (i) continue label; else break label; }",
            "switch (x) { case 1: f(); break; default: g(); }",
            "try { f(); } catch { g(); } finally { h(); }",
            "import d, { a as b, default as c } from 'm'; import * as ns from 'n'; import 'side';",
            "export default function () {} export { a as b }; export * from 'x'; export * as y from 'z';",
            "const m = import('m'); const u = import.meta.url; new.target;",
            "const t = tag`a${b}c${`d${e}`}f`;",
            "x = a ? b : c ? d : e; y = (a, b); z = () => ({ k: 1 }); w = async x => x;",
            "if (a) b(); else if (c) d(); else e();",
            "do x++; while (x < 3)",
            "const re = /[/]+\\d/giu; const div = a / b / c;",
        ],
    )
    def test_each_form_parses_clean(self, source: str) -> None:
        assert Parsed.errors(source) == 0

    def test_automatic_semicolon_insertion(self) -> None:
        assert Parsed.errors("let a = 1\nlet b = 2\na\n++b\nreturn\n") == 0

    def test_a_get_or_set_member_is_a_name_when_no_key_follows(self) -> None:
        assert Parsed.errors("const o = { get, set, get: 1 }; class C { get() {} set(v) {} }") == 0


class TestTypeScript:
    @pytest.mark.parametrize(
        "source",
        [
            "g.fetch = async (input: any, init: any = {}) => { return 1; };",
            "const m = new Map<string, { positive?: Option; negative?: Option }>();",
            "declare global { interface Window { x: number } }",
            "declare const require: { context(path: string): any };",
            "declare function f<K extends keyof M>(tag: K): M[K];",
            "export class A extends LitElement { @property({ type: String }) name = ''; }",
            "class C { private readonly b: string; constructor(private h: H, public x?: number) {} }",
            "type S<N extends string, T> = { [P in N]: T[K] };",
            "abstract class A { protected abstract f(b: Buffer): void; }",
            "namespace N.M { export const x = 1; }",
            "enum E { A = 1, B }",
            "import cp = require('child_process');",
            "const f = (e): e is { path: string } => typeof e.path === 'string';",
            "function g<T>(x: T): asserts x is NonNullable<T> {}",
            "let v = <string>u; let w = u as unknown as T; let s = u satisfies T;",
        ],
    )
    def test_each_form_parses_clean(self, source: str) -> None:
        assert Parsed.errors(source, typescript=True, jsx=False) == 0

    def test_a_namespace_body_is_code_that_runs(self) -> None:
        assert "CallExpression" in Parsed.types("namespace N { run(); }", typescript=True)

    def test_an_abstract_class_body_is_kept(self) -> None:
        assert "CallExpression" in Parsed.types(
            "abstract class A { f() { return g(); } }", typescript=True
        )


class TestJsx:
    def test_elements_and_expressions(self) -> None:
        source = "const v = <div a='1' {...p}>{x ? <b/> : null} text </div>;"
        assert Parsed.errors(source) == 0

    def test_a_closing_tag_is_not_a_regex(self) -> None:
        assert Parsed.errors("const v = <p>a / b</p>;") == 0


class TestRecovery:
    def test_a_malformed_statement_costs_only_itself(self) -> None:
        types = Parsed.types("const const = ;\nrun();\n")
        assert "Error" in types
        assert "CallExpression" in types

    def test_an_unclosed_block_does_not_swallow_the_file(self) -> None:
        assert "CallExpression" in Parsed.types("function f() {\n  if (x {\n}\nlater();\n")

    def test_deep_nesting_is_bounded_not_a_crash(self) -> None:
        Parser("(" * 50_000 + "x" + ")" * 50_000).program()
        Parser("[" * 50_000).program()
        Parser("a" + "?.b" * 20_000).program()

    def test_random_input_always_terminates_without_an_exception(self) -> None:
        rng = random.Random(11)  # noqa: S311 -- a reproducible fuzz input, not a secret
        alphabet = "ab(){}[]<>/'\"`$;:,.=+-*!?\\\n #@0x"
        for _ in range(400):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
            for typescript in (False, True):
                assert isinstance(Parser(text, typescript=typescript).program(), Node)

    def test_time_is_linear_in_the_input(self) -> None:
        unit = "const a = require('m'); a.f(b, `t${c}`, /r/g, x => ({ y: [1, 2] }));\n"

        def cost(n: int) -> float:
            """The best of five runs: on a loaded machine one run measures the machine."""
            text = unit * n
            best = float("inf")
            for _ in range(5):
                start = time.perf_counter()
                Parser(text).program()
                best = min(best, time.perf_counter() - start)
            return best

        small, large = cost(500), cost(4_000)
        assert large < small * 8 * 3
