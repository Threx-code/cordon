"""rule_engine.gates: the parts of a condition read before any string is searched. Every rule here is
matched twice, gated and with its gates and clauses removed, over the same files, and the matches
(rules and string instances) must be the same; then what the gates hold is checked by name."""

from __future__ import annotations

import re
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import Rules

FILES = [
    b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"abc evil.com xyz" * 4,
    b"\x7fELF" + b"\x00" * 60 + b"needle here and there",
    b"plain text with abc and def and ghi",
    b"",
    b"abc" * 1000,
]
CONDITIONS = [
    "$a and uint16(0) == 0x5A4D",
    "uint16(0) == 0x5A4D and ($a or $b)",
    "filesize < 100 and any of them",
    "$a and $b and filesize > 10",
    "($a or $c) and ($b or $c)",
    "all of ($a, $b) and uint32(0) == 0x464c457f",
    "2 of them and filesize > 0",
    "not $a and filesize > 5",
    "$a or filesize < 10",
    "#a > 2 and filesize > 1",
    "any of ($a*) and $b",
    "none of them and filesize > 0",
    "50% of them and filesize > 0",
    "$a at 0 and filesize > 2",
    "for any i in (1..#a): (@a[i] > 5) and filesize > 0",
    "r0 and $a",
    "$a and defined uint32(1000)",
]
STRINGS = {"$a": '"abc"', "$a2": '"evil"', "$b": '"def"', "$c": '"needle"'}


class Ungated:
    @staticmethod
    def matches(rules: Rules, data: bytes) -> list[Any]:
        return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))

    @staticmethod
    def source(condition: str) -> str:
        """The rule with the strings its condition names (every one for `them`, a prefix's for `$a*`)."""
        names = [
            n for n in STRINGS
            if "them" in condition or re.search(re.escape(n) + r"(?![0-9A-Za-z_])", condition.replace("#", "$").replace("@", "$"))
            or ("$a*" in condition and n.startswith("$a"))
        ]  # fmt: skip
        strings = " ".join(f"{n} = {STRINGS[n]}" for n in names)
        return f"rule r0 {{ condition: filesize > 3 }} rule r {{ strings: {strings} condition: {condition} }}"


class TestTheSameMatches:
    @pytest.mark.parametrize("condition", CONDITIONS)
    def test_gated_and_ungated_agree(self, condition: str) -> None:
        gated, plain = (
            Rules.compile(Ungated.source(condition)),
            Rules.compile(Ungated.source(condition)),
        )
        for rule in plain.rules:
            rule.gates, rule.clauses = [], []
        for data in FILES:
            assert Ungated.matches(gated, data) == Ungated.matches(plain, data)


class TestWhatIsGated:
    @staticmethod
    def rule(condition: str) -> Any:
        return Rules.compile(Ungated.source(condition)).rules[1]

    def test_clauses(self) -> None:
        assert self.rule("$a and ($b or $c)").clauses == [
            frozenset({"$a"}),
            frozenset({"$b", "$c"}),
        ]
        assert self.rule("all of ($a, $b)").clauses == [frozenset({"$a"}), frozenset({"$b"})]
        assert self.rule("any of ($a*)").clauses == [frozenset({"$a", "$a2"})]
        assert self.rule("$a or filesize < 10").clauses == []
        assert self.rule("not $a").clauses == [] and self.rule("none of them").clauses == []
        assert self.rule("50% of them").clauses == [] and self.rule("#a > 2").clauses == []

    def test_gates_are_the_parts_that_read_no_string(self) -> None:
        assert len(self.rule("$a and uint16(0) == 0x5A4D and filesize > 2").gates) == 2
        assert self.rule("$a or uint16(0) == 0x5A4D").gates == []
        assert self.rule("uint16(0) == 0x5A4D").gates == []  # nothing to save without strings

    def test_a_rule_that_logs_is_not_gated(self) -> None:
        r = Rules.compile(
            'import "console" rule r { strings: $a = "abc" condition: $a and console.log("x") }'
        )
        assert r.rules[0].gates == [] and r.rules[0].clauses == []
