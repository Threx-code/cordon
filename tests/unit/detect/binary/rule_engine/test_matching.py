"""cordon-rule string matching: where each string matches, offset and length, for the shapes whose
answer depends on how the search runs -- anchors, the forward and backward runs, linked hex parts,
the text modifiers. Each expected answer was taken from the reference engine on the same rule and
data; the generative differential (random rules over random data) holds the same at scale."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.pattern import Memo, PatternError, RegexReader

DOTS = b"."


class TestWhereStringsMatch:
    @pytest.mark.parametrize(
        ("spec", "data", "want"),
        [
            ("/a??/", b"xaa", [(1, 1), (2, 1)]),
            ("/a+/", b"aaaa", [(0, 4), (1, 3), (2, 2), (3, 1)]),
            ("/[a-z]*/", b"ab1", [(0, 2), (1, 1), (2, 0)]),
            ("/(base64|ab)?/", b"zzab", [(2, 2)]),
            ("/t?[a-z]/", b"atb", [(1, 2)]),
            ("/a.*?b/", b"aabab", [(0, 3), (1, 2), (3, 2)]),
            ("/a.*b/", b"aabab", [(0, 5), (1, 4), (3, 2)]),
            ("/(a|ab)(c|bcd)/", b"abcd", [(0, 4)]),
            ("/ab{2,3}/", b"abbbb", [(0, 4)]),
            ("/ab{2,3}?/", b"abbbb", [(0, 3)]),
            ("/x(ab){2}y/", b"xababy", [(0, 6)]),
            ("/\\bab\\b/", b"ab ab_ab", [(0, 2)]),
            ("/^ab/", b"abab", [(0, 2)]),
            ("/ab$/", b"abab", [(2, 2)]),
            ("/[^a]/ wide nocase fullword", b'd\x00"\x00x', [(0, 2)]),
            ('"powershell" wide base64', b"cABvAHcAZQByAHMAaABlAGwAbAA=", [(0, 26)]),
            ('"Rich" xor(1-3)', bytes(c ^ 2 for c in b"..Rich.."), [(2, 4)]),
            ('"ab" xor wide', bytes([0x61 ^ 5, 5, 0x62 ^ 5, 5]), [(0, 4)]),
            ('"ab" ascii wide', b"ab a\x00b\x00", [(0, 2), (3, 4)]),
            ('"abcde" nocase wide', b"A\x00b\x00C\x00d\x00E\x00", [(0, 10)]),
            ("{ 61 [2-4] 62 }", b"a..b..b", [(0, 4)]),
            ("{ 61 [0-2] 62 }", b"aaab", [(0, 4), (1, 3), (2, 2)]),
            ("{ 61 ?? ( 62 | 63 ) }", b"axbaxc", [(0, 3), (3, 3)]),
            ("{ 61 62 [300-400] 63 64 }", b"ab" + DOTS * 350 + b"cd", [(0, 354)]),
            ("{ 61 62 [250] 63 64 }", b"ab" + DOTS * 250 + b"cdab", [(0, 254)]),
            ("{ 6? ?? [0-] 72 6C }", b"ab" + DOTS * 5000 + b"rl", [(0, 5004), (1, 5003)]),
            ('"ab" fullword', b"ab xab ab_ ab.", [(0, 2), (7, 2), (11, 2)]),
            ("/a{0}b/", b"ab", [(1, 1)]),
        ],
    )
    def test_offsets_and_lengths(self, spec: str, data: bytes, want: list[tuple[int, int]]) -> None:
        rules = Rules.compile("rule r { strings: $a = " + spec + " condition: $a }")
        got = [(at, len(text)) for m in rules.match(data) for at, _, text in m.strings]
        assert got == want

    def test_a_string_used_only_at_one_offset_counts_only_there(self) -> None:
        rules = Rules.compile('rule r { strings: $a = "ab" condition: $a at 2 }')
        assert [m.strings for m in rules.match(b"abab")] == [[(2, "$a", b"ab")]]


class TestRegexArguments:
    def test_a_function_taking_a_regular_expression_gets_one(self) -> None:
        rules = Rules.compile(
            'import "tests" rule r { condition: tests.match(/b+c/, "abbbcd") == 5 }',
            modules={"tests": TestRegexArguments.module()},
        )
        assert rules.match(b"")

    @staticmethod
    def module() -> Any:
        from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Sig

        def match(m: Any, s: bytes) -> int:
            return int(m.run(s.split(b"\x00", 1)[0]))

        schema = Record({"match": Call(Sig(("regex", "text"), Scalar.INT))})
        return Module(schema, lambda file: {"match": (match,)})


class TestPatternsRefused:
    @pytest.mark.parametrize(
        "spec",
        [
            "/a*b+?/",  # eager and lazy repeats in one expression
            "/(a)\\1/",
            "/a{40000}/",
            "/a{3,1}/",
            "/[z-a]/",
            "/\\x4/",
            "{ 61 ( 62 [0-] | 63 ) 64 }",
            "{ 61 ( 62 [201] 63 | 64 ) 65 }",
            "{ [2] 61 }",
            "{ 61 6 }",
        ],
    )
    def test_refused(self, spec: str) -> None:
        with pytest.raises(RuleError):
            Rules.compile("rule r { strings: $a = " + spec + " condition: $a }")

    def test_the_reader_names_the_problem(self) -> None:
        with pytest.raises(PatternError, match="backreferences"):
            RegexReader(b"(a)\\1").read()


class TestRobustness:
    @pytest.mark.parametrize("spec", ["/a{0,0}?/s fullword", "/c{0}?/i", "/(x{0})+y/"])
    def test_repeats_of_nothing_match_nothing_and_never_fail(self, spec: str) -> None:
        rules = Rules.compile("rule r { strings: $a = " + spec + " condition: $a or true }")
        assert rules.match(b"cxy" * 10)

    def test_a_brace_inside_a_hex_comment_does_not_end_the_string(self) -> None:
        rules = Rules.compile("rule r { strings: $a = { 61 /* } */ 62 } condition: $a }")
        assert rules.match(b"ab")

    def test_the_step_memo_is_bounded(self) -> None:
        memo = Memo()
        for i in range(Memo.LIMIT + 10):
            memo.remember((i,), (0, 0))
        assert len(memo.steps) <= Memo.LIMIT

    def test_a_whole_alphabet_of_base64_forms_is_found(self) -> None:
        text = base64.b64encode(b"..hello world..")
        rules = Rules.compile('rule r { strings: $a = "hello world" base64 condition: $a }')
        assert rules.match(text)
