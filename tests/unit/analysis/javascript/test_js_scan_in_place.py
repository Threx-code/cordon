"""The token scan that reads a template's `${}` in place gives exactly the tokens of the scan that re-sliced the text for each one.

`tests/kits/js_scan_before.py` keeps the scan as it was. Every token (kind, value, start, end) of the two must be identical, with
and without template expansion, on the repository's JavaScript corpus, on invented nested-template fixtures (comments, strings,
regular expressions and braces inside `${}`, unterminated templates, nesting past the depth cap) and on generated text.
The last test times 5 MB of nested templates.
"""

from __future__ import annotations

import os
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.analysis.javascript.js_eval import JsEval
from kits.js_scan_before import ReferenceScan
from support import ROOT

EXAMPLES = int(os.environ.get("CORDON_SCAN_EQUIVALENCE_EXAMPLES", "300"))


class Both:
    @staticmethod
    def same(text: str) -> None:
        for templates in (False, True):
            before = [
                (t.kind, t.value, t.start, t.end) for t in ReferenceScan._scan(text, templates, 0)
            ]
            after = [(t.kind, t.value, t.start, t.end) for t in JsEval._scan(text, templates, 0)]
            assert after == before, (templates, text[:120])


class Fixtures:
    TEXTS = (
        "`a${b}c`",
        "`a${`b${c}d`}e`",
        "`${ {a: 1}.a }x${ '}' }y${ \"}\" }z`",
        "`${ /* } */ 1 }` + `${ 2 // }\n}`",
        "`${ /[}]/.test(x) }` ; `${ a / b }`",
        "`${ `${ `${ x }` }` }`",
        "`a${",
        "`a${b",
        "`a${b}",
        "`${` `${` `${`",
        "`\\${x}` + `\\`${y}\\``",
        "`${a}` + '${b}' + \"${c}\" + `${d}`",
        "x = `${ y = `${ z }` }`; w = `u`",
        "`${ a ? `${b}` : `${c}` }`",
        "}` `${ `",
        "`${\n// comment `\n}`",
        "`${ /* unterminated `",
        "`" + "${" * 40 + "x" + "}" * 40 + "`",
    )

    @staticmethod
    def nested(depth: int) -> str:
        return "`a${" * depth + "x" + "}b`" * depth


class TestTheSameTokensAsBefore:
    @pytest.mark.parametrize("text", Fixtures.TEXTS)
    def test_each_invented_fixture(self, text: str) -> None:
        Both.same(text)

    @pytest.mark.parametrize("depth", [1, 2, 8, 15, 16, 17, 18, 40, 200])
    def test_nesting_up_to_and_past_the_cap(self, depth: int) -> None:
        Both.same(Fixtures.nested(depth))
        Both.same(Fixtures.nested(depth) + ";" + Fixtures.nested(depth))

    def test_every_javascript_file_of_the_repositorys_corpus(self) -> None:
        files = sorted((ROOT / "corpus").rglob("*.js")) + sorted((ROOT / "tests").rglob("*.js"))
        assert files
        for path in files:
            if path.stat().st_size < 400_000:
                Both.same(path.read_text(encoding="utf-8", errors="replace"))

    @settings(
        max_examples=EXAMPLES,
        deadline=None,
        database=None,
        suppress_health_check=list(HealthCheck),
        derandomize=True,
    )
    @given(
        st.lists(
            st.sampled_from(
                [
                    "`",
                    "${",
                    "}",
                    "{",
                    "'",
                    '"',
                    "/",
                    "/*",
                    "*/",
                    "//",
                    "\n",
                    " ",
                    "\\",
                    "a",
                    "1",
                    "(",
                    ")",
                    "+",
                    ";",
                    "x=",
                    "return ",
                ]
            ),
            max_size=80,
        ).map("".join)
    )
    def test_generated_text(self, text: str) -> None:
        Both.same(text)


class TestFiveMegabytesOfNestedTemplates:
    def test_it_is_scanned_in_linear_time(self) -> None:
        block = Fixtures.nested(15) + ";\n"
        text = block * (5_000_000 // len(block))
        began = time.perf_counter()
        count = len(JsEval._scan(text, True, 0))
        seconds = time.perf_counter() - began
        assert count > 100_000
        assert seconds < 30.0, f"{len(text) / 1e6:.1f} MB took {seconds:.1f} s"
