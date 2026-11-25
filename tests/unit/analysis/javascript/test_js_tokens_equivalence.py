"""The tokenizer reads a file the way it always did (golden digests of its tokens for fixed inputs, nesting past the template depth included),
and nested templates cost what flat ones cost per token, at every size: no quadratic return."""

from __future__ import annotations

import hashlib
import time

import pytest

from cordon_scanner.analysis.javascript.evaluation.values import MAX_TEMPLATE_DEPTH
from cordon_scanner.analysis.javascript.js_eval import JsEval


class Fixtures:
    @staticmethod
    def nest(levels: int, inner: str = "1", wrap: str = "a") -> str:
        return "x = " + (f"`{wrap}${{") * levels + inner + ("}b`") * levels + ";\n"

    @classmethod
    def texts(cls) -> dict[str, str]:
        return {
            "plain": "const a = \"x\" + 'y'; let n = 0x1F + 1.5e3; // c\n/* b */ f(a, n);\n",
            "regex": "const r = /ab+c/gi; const d = a / b / c; x = y / 2; if (/\\d+/.test(s)) {}\n",
            "template": "const t = `a${b}c${d + `e${f}g`}h`; const u = `no substitution`;\n",
            "template_object": "const t = `a${ {k: `v${w}`}.k }b`;\n",
            "template_escape": "const t = `a\\${b}c\\`d${e}`;\n",
            "unterminated_template": "const t = `a${b} oops\nnext(1);\n",
            "unterminated_string": "const s = 'abc\nnext(2);\n",
            "unterminated_substitution": "const t = `a${b + \n",
            "deep_ok": cls.nest(40),
            "deeper_than_the_limit": cls.nest(400),
            "unclosed_deep": "x = " + "`a${" * 400 + "1" + "}b`" * 399 + ";\n",
            "long_string": 'const s = "' + "a" * 5000 + '"; f(s);\n',
            "punct": "a ?? b; a?.b; a ?. 5; a **= 2; a >>>= 1; x => y; ...z; a && b || !c;\n",
            "mixed": "f(`x${y}`, /re/, 'q', 12, `t${`u${v}`}`); // end\n",
            "comma_zero": "(0, os_1.hostname)();\n",
            "levels_15": cls.nest(MAX_TEMPLATE_DEPTH - 1),
            "levels_16": cls.nest(MAX_TEMPLATE_DEPTH),
            "levels_17": cls.nest(MAX_TEMPLATE_DEPTH + 1),
            "levels_18": cls.nest(MAX_TEMPLATE_DEPTH + 2),
            "strings_and_braces_inside": cls.nest(5, inner="{a: \"}\"}.a + '}' + `}${z}`"),
            "braces_in_levels_17": cls.nest(MAX_TEMPLATE_DEPTH + 1, inner="{a: {b: 1}}.a.b"),
            "newline_in_a_quote_inside": "t = `a${ 'x\ny' + `b${c}` }d`;\n",
            "two_siblings_then_deep": "a = `p${1}q${2}`; " + cls.nest(MAX_TEMPLATE_DEPTH + 3),
            "deep_with_an_unclosed_tail": cls.nest(MAX_TEMPLATE_DEPTH + 3)[:-6],
            "escape_at_the_end": "t = `a${b}\\",
        }


class Tokens:
    @staticmethod
    def digest(text: str, templates: bool) -> str:
        found = JsEval.tokens(text, templates=templates)
        return hashlib.sha256(
            repr([(t.kind, t.value, t.start, t.end) for t in found]).encode()
        ).hexdigest()[:16]

    @staticmethod
    def seconds(text: str) -> float:
        """The time to tokenize `text` with its templates read, the best of three on texts the memo has not seen."""
        best = float("inf")
        for attempt in range(3):
            fresh = text + f"// {attempt}\n"
            started = time.perf_counter()
            JsEval.tokens(fresh, templates=True)
            best = min(best, time.perf_counter() - started)
        return best


#: The digest of the tokens of each fixture, with and without `templates`, as the tokenizer made them before the one-pass matcher of `${...}`.
GOLDEN: dict[tuple[str, bool], str] = {
    ("braces_in_levels_17", False): "d7814157a8ea03af",
    ("braces_in_levels_17", True): "6395fd0e3a260e5f",
    ("comma_zero", False): "3409ca0a83f5e4b8",
    ("comma_zero", True): "3409ca0a83f5e4b8",
    ("deep_ok", False): "016c2e9fb998b8c4",
    ("deep_ok", True): "6c5aaaa4ea0633f3",
    ("deep_with_an_unclosed_tail", False): "444835b44edba30c",
    ("deep_with_an_unclosed_tail", True): "fc58355f515accf9",
    ("deeper_than_the_limit", False): "66493b1b7964a6b5",
    ("deeper_than_the_limit", True): "589fa40ee79bd345",
    ("escape_at_the_end", False): "d8c5fcb4a9617b51",
    ("escape_at_the_end", True): "d8c5fcb4a9617b51",
    ("levels_15", False): "0a5d9225f5b70477",
    ("levels_15", True): "7eb327574339ff92",
    ("levels_16", False): "c31c2501e3c1ae93",
    ("levels_16", True): "7bc897f867eaa4b5",
    ("levels_17", False): "65e3bf34f8a9d38d",
    ("levels_17", True): "e27aaab8840424e1",
    ("levels_18", False): "cc1acedf04ef2e6b",
    ("levels_18", True): "79764859e0be2a8b",
    ("long_string", False): "184dc9525beb2d2c",
    ("long_string", True): "184dc9525beb2d2c",
    ("mixed", False): "f67aea35ae3ed3cc",
    ("mixed", True): "9997fd723667f7d0",
    ("newline_in_a_quote_inside", False): "0db1b6a70ddf97bf",
    ("newline_in_a_quote_inside", True): "0db1b6a70ddf97bf",
    ("plain", False): "c8cb27763d7efd90",
    ("plain", True): "c8cb27763d7efd90",
    ("punct", False): "3bffcfb31feb7fa2",
    ("punct", True): "3bffcfb31feb7fa2",
    ("regex", False): "00a1db3e1a514a6a",
    ("regex", True): "00a1db3e1a514a6a",
    ("strings_and_braces_inside", False): "0c2d061fdd5f51cf",
    ("strings_and_braces_inside", True): "4926d700a8d76035",
    ("template", False): "5bd748f0fb3e1e2b",
    ("template", True): "c3fd058197449d91",
    ("template_escape", False): "0a79798fbf9ac915",
    ("template_escape", True): "a9a4e4fcd410035b",
    ("template_object", False): "cd061ec033a4e63f",
    ("template_object", True): "99c67db1348b8529",
    ("two_siblings_then_deep", False): "7a6dfc9cbf868445",
    ("two_siblings_then_deep", True): "0631475a16a3c24f",
    ("unclosed_deep", False): "5f332ec3e438c2ec",
    ("unclosed_deep", True): "6be27b8863ab7ce2",
    ("unterminated_string", False): "7800aa4801ff6b47",
    ("unterminated_string", True): "7800aa4801ff6b47",
    ("unterminated_substitution", False): "b8c39f42fe73183b",
    ("unterminated_substitution", True): "b8c39f42fe73183b",
    ("unterminated_template", False): "8823685317e035f0",
    ("unterminated_template", True): "8823685317e035f0",
}


class TestTheTokensAreTheSame:
    @pytest.mark.parametrize("name", sorted(Fixtures.texts()))
    @pytest.mark.parametrize("templates", [False, True])
    def test_a_fixture_reads_as_it_always_did(self, name: str, templates: bool) -> None:
        assert Tokens.digest(Fixtures.texts()[name], templates) == GOLDEN[(name, templates)]

    def test_every_fixture_has_a_digest(self) -> None:
        assert {(name, t) for name in Fixtures.texts() for t in (False, True)} == set(GOLDEN)


class TestNestedTemplatesCostWhatFlatOnesCost:
    FLAT = "x = `a${b}c`;\n"
    NESTED = Fixtures.nest(2000)

    @classmethod
    def sized(cls, unit: str, megabytes: float) -> str:
        return unit * max(1, int(megabytes * 1_000_000) // len(unit))

    def test_per_token_a_nested_file_is_within_four_times_a_flat_one_at_each_size(self) -> None:
        for megabytes in (1, 2):
            flat, nested = self.sized(self.FLAT, megabytes), self.sized(self.NESTED, megabytes)
            per_flat = Tokens.seconds(flat) / len(JsEval.tokens(flat, templates=True))
            per_nested = Tokens.seconds(nested) / len(JsEval.tokens(nested, templates=True))
            # Measured 1.7 to 2.4 on a quiet machine (a nested token does more work than a flat one); the quadratic scan this guards against
            # was two to three orders of magnitude slower per token, so four times is a bound it cannot meet and a loaded machine does not break.
            assert per_nested <= 4 * per_flat, (megabytes, per_nested / per_flat)

    def test_time_grows_with_size_and_no_faster(self) -> None:
        one = Tokens.seconds(self.sized(self.NESTED, 1))
        five = Tokens.seconds(self.sized(self.NESTED, 5))
        assert five <= 3 * 5 * one, (one, five)
