"""rule_engine.lang.Plan: a match visits only the rules a string with an anchor in the file can
reach, and those that may hold with no match; every other rule is decided false unvisited. Random
rule sets (global and private rules, rules naming earlier rules, rules with no strings, conditions
true without a match: `not $a`, `#a == 0`, `none of them`, a count, a percentage) over random data
are matched with the Plan and with every rule visited, and the matches must be the same; the number
of cases is CORDON_PLAN_EXAMPLES (300 by default; the proof runs 100,000)."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import lang
from cordon_scanner.detect.binary.rule_engine.lang import Plan, RuleError, Rules

EXAMPLES = int(os.environ.get("CORDON_PLAN_EXAMPLES", "300"))
STRINGS = ['"ab"', '"zz"', "{ 61 ?? 62 }", "/b+a/", '"AB" nocase', '"q"']
CONDITIONS = [
    "$a", "$a and $b", "$a or $b", "not $a", "#a == 0", "none of them", "any of them", "all of them",
    "#a > 1", "50% of them", "$a at 0", "filesize > 3", "$a or filesize < 5", "uint8(0) == 0x61",
]  # fmt: skip
DATA = st.binary(max_size=60) | st.lists(
    st.sampled_from([b"ab", b"zz", b"q", b"AB", b"bba", b"x"]), max_size=20
).map(b"".join)


class Everything(Plan):
    """A plan that visits every rule, as the loop did before plans."""

    def __init__(self, rules: list[lang.RuleDef]) -> None:
        super().__init__(rules)
        self.always = list(range(len(rules)))
        self.by_string, self.global_skippable = {}, []


class Both:
    @staticmethod
    def matches(source: str, data: bytes, planned: bool, monkeypatch: pytest.MonkeyPatch) -> object:
        try:
            rules = Rules.compile(source)
        except RuleError:
            return "does not compile"
        if not planned:
            monkeypatch.setattr(rules, "_plan", Everything(rules.rules))
        return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))


RULE = st.tuples(
    st.lists(st.sampled_from(STRINGS), min_size=0, max_size=2, unique=True),
    st.sampled_from(CONDITIONS),
    st.sampled_from(["", "global ", "private "]),
    st.booleans(),
)


class TestThePlan:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(rules=st.lists(RULE, min_size=1, max_size=5), data=DATA)
    def test_planned_and_every_rule_agree(
        self,
        rules: list[tuple[list[str], str, str, bool]],
        data: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        source = []
        for i, (strings, condition, kind, names_earlier) in enumerate(rules):
            names = ["$a", "$b"][: len(strings)]
            if not strings:
                condition = (
                    "filesize > 3"
                    if "$" in condition or "of them" in condition or "#" in condition
                    else condition
                )
            elif len(strings) == 1:
                condition = condition.replace("$b", "$a")
            if names_earlier and i > 0:
                condition = f"({condition}) or r{i - 1}"
            body = " ".join(f"{n} = {s}" for n, s in zip(names, strings, strict=False))
            part = f"strings: {body} " if strings else ""
            source.append(f"{kind}rule r{i} {{ {part}condition: {condition} }}")
        text = " ".join(source)
        assert Both.matches(text, data, True, monkeypatch) == Both.matches(
            text, data, False, monkeypatch
        )
