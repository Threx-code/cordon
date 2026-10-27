"""Cordon's YARA engine (`detect/binary/yara_lang`), held to YARA's own test suite.

`data/yara/yara-4.5.1-test-rules.json` is every case of YARA's `tests/test-rules.c` whose rule
and data are literals: it matches, it does not, or it does not compile. Each is run here with the
external variables and the `tests` module YARA's harness provides, and must come out as YARA says.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.rule_values import (
    UNDEF_FLOAT,
    UNDEF_INT,
    UNDEF_STR,
    Array,
    Dictionary,
    Struct,
    Values,
)
from cordon_scanner.detect.binary.yara_lang import Rules, YaraError
from support import ROOT


class YaraTests:
    """YARA's `tests` module (`libyara/modules/tests/tests.c`, v4.5.1), as its harness loads it."""

    EXTERNALS: ClassVar[dict[str, Any]] = {
        "var_zero": 0,
        "var_one": 1,
        "var_true": True,
        "var_false": False,
    }
    CASES: ClassVar[list[dict[str, str]]] = json.loads(
        (ROOT / "tests" / "unit" / "data" / "yara" / "yara-4.5.1-test-rules.json").read_text(
            encoding="utf-8"
        )
    )

    @staticmethod
    def module(data: bytes) -> Struct:
        def match(pattern: Any, s: bytes) -> int:
            # the text up to its first zero byte, as the tests module reads it
            return int(pattern.run(s.split(b"\x00", 1)[0]))

        proto = Struct({"i": UNDEF_INT, "s": UNDEF_STR})
        inner = Struct(
            {
                "struct_array": Array(Struct({"unused": UNDEF_STR})),
                "struct_dict": Dictionary(Struct({"unused": UNDEF_STR})),
            }
        )
        return Struct(
            {
                "constants": Struct({"one": 1, "two": 2, "foo": b"foo", "empty": b""}),
                "undefined": Struct({"i": UNDEF_INT, "f": UNDEF_FLOAT}),
                "module_data": UNDEF_STR,
                "integer_array": Array(UNDEF_INT, {0: 0, 1: 1, 2: 2, 256: 256}),
                "string_array": Array(
                    UNDEF_STR, {0: b"foo", 1: b"bar", 2: b"baz", 3: b"foo\x00bar"}
                ),
                "integer_dict": Dictionary(UNDEF_INT),
                "string_dict": Dictionary(UNDEF_STR, {b"foo": b"foo", b"bar": b"bar"}),
                "struct_array": Array(proto, {1: Struct({"i": 1, "s": UNDEF_STR})}),
                "struct_dict": Dictionary(proto, {b"foo": Struct({"i": 1, "s": b"foo"})}),
                "empty_struct_dict": Dictionary(Struct({"unused": UNDEF_INT})),
                "empty_struct_array": Array(inner),
                "match": Values.fn((("r", "str"), match, "int")),
                "isum": Values.fn(
                    (("int", "int"), lambda a, b: a + b, "int"),
                    (("int", "int", "int"), lambda a, b, c: a + b + c, "int"),
                ),
                "fsum": Values.fn(
                    (("float", "float"), lambda a, b: float(a + b), "float"),
                    (("float", "float", "float"), lambda a, b, c: float(a + b + c), "float"),
                ),
                "length": Values.fn((("str",), len, "int")),
                "empty": Values.fn(((), lambda: b"", "str")),
                "foobar": Values.fn(
                    (("int",), lambda n: b"foo" if n == 1 else b"bar" if n == 2 else b"oops", "str")
                ),
            }
        )

    @staticmethod
    def outcome(rule: str, data: bytes) -> str:
        try:
            rules = Rules.compile(rule, YaraTests.EXTERNALS, {"tests": YaraTests.module})
        except YaraError:
            return "error"
        return "true" if rules.match(data, timeout=20) else "false"


class TestYarasOwnSuite:
    @pytest.mark.parametrize("index", range(len(YaraTests.CASES)))
    def test_each_case_comes_out_as_yara_says(self, index: int) -> None:
        case = YaraTests.CASES[index]
        got = YaraTests.outcome(case["rule"], base64.b64decode(case["data"]))
        assert got == case["expect"], case["rule"]


class TestMatches:
    """Behaviour checked against yara-python 4.5.1 when this was written."""

    @pytest.mark.parametrize(
        ("rule", "data", "offsets"),
        [
            (
                "rule r { strings: $a = /a+/ condition: $a }",
                b"aaaa",
                [(0, 4), (1, 3), (2, 2), (3, 1)],
            ),
            ('rule r { strings: $a = "aa" condition: $a }', b"aaaa", [(0, 2), (1, 2), (2, 2)]),
            (
                "rule r { strings: $a = { 61 [0-2] 62 } condition: $a }",
                b"aaab",
                [(0, 4), (1, 3), (2, 2)],
            ),
            (
                'rule r { strings: $a = "ab" fullword condition: $a }',
                b"ab xab ab_ ab.",
                [(0, 2), (7, 2), (11, 2)],
            ),
            (
                'rule r { strings: $a = "ab" wide ascii condition: $a }',
                b"ab a\x00b\x00",
                [(0, 2), (3, 4)],
            ),
            (
                'rule r { strings: $a = "Ab" nocase condition: $a }',
                b"ab AB aB",
                [(0, 2), (3, 2), (6, 2)],
            ),
        ],
    )
    def test_every_start_is_a_match_as_yara_reports(
        self, rule: str, data: bytes, offsets: list
    ) -> None:
        (match,) = Rules.compile(rule).match(data)
        assert [(at, len(text)) for at, _, text in match.strings] == offsets

    def test_base64_at_every_alignment(self) -> None:
        rule = Rules.compile('rule r { strings: $a = "This program cannot" base64 condition: $a }')
        for prefix in (b"", b"z", b"zz"):
            assert rule.match(base64.b64encode(prefix + b"This program cannot be run"))


class TestHostileInput:
    def test_a_whitespace_flood_does_not_make_a_regex_slow(self) -> None:
        rules = Rules.compile(r"rule r { strings: $a = /\s*\(/ condition: $a }")
        started = time.perf_counter()
        assert not rules.match(b" " * 2_000_000, timeout=60)
        assert time.perf_counter() - started < 60

    def test_an_expression_re_would_backtrack_on_runs_on_the_linear_engine(self) -> None:
        rules = Rules.compile(r"rule r { strings: $a = /(\s*,\s*\d{1,3}){19,}x/ condition: $a }")
        started = time.perf_counter()
        assert not rules.match(b"1" + b" , 1" * 5000 + b"y", timeout=60)
        assert time.perf_counter() - started < 60

    def test_the_deadline_stops_matching(self) -> None:
        rules = Rules.compile("rule r { strings: $a = { 61 [-] 62 } condition: $a }")
        with pytest.raises(YaraError, match="longer than the time allowed"):
            rules.match(b"a" * 3_000_000, timeout=0.001)

    def test_includes_are_refused(self) -> None:
        with pytest.raises(YaraError, match="include"):
            Rules.compile('include "x.yar"\nrule r { condition: true }')
