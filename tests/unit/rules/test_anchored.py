"""The anchored search finds exactly what finditer finds: the same matches, in the same order."""

from __future__ import annotations

import random
import re

import pytest

from cordon_scanner.rules.anchored import AnchoredSearch


class AnchorKit:
    @staticmethod
    def both(pattern: bytes, data: bytes, flags: int = 0) -> list[tuple[tuple[int, int], bytes]]:
        compiled = re.compile(pattern, flags)
        want = [(m.span(), m.group(0)) for m in compiled.finditer(data)]
        plan = AnchoredSearch.plan(compiled)
        got = [
            (m.span(), m.group(0))
            for m in AnchoredSearch.matches(compiled, plan, data, data.lower())
        ]
        assert got == want, (pattern, plan)
        return got


class TestExact:
    @pytest.mark.parametrize(
        "pattern",
        [
            rb"\bfetch\s*\(",
            rb"(?:\bfetch\s*\()|(?:\baxios\s*\.\s*get\s*\()",
            rb"ab(?:cde|cd)",  # the first alternative that matches wins, not the longest
            rb"(?:xx)?token[0-9]{1,3}",  # an optional prefix before the anchor
            rb"(?<=key=)secret\w+",  # lookbehind sees the bytes before the candidate
            rb"(?:\$\(\w+)|(?:\bcurl\b.{0,40}\|\s*sh)",  # one alternative has no anchor
            rb"(?:`[a-z]+`)|(?:\beval\s*\()",
        ],
    )
    def test_same_matches_as_finditer(self, pattern: bytes) -> None:
        text = (
            b"x fetch( axios . get( abcde abcd xxtoken12 token999 key=secretABC "
            b"$(whoami) curl http://h | sh `id` eval ( fetchfetch( afetch( "
        )
        AnchorKit.both(pattern, text * 3)

    def test_case_folded_anchors(self) -> None:
        got = AnchorKit.both(rb"\bFETCH\s*\(", b"Fetch( FETCH( fetch( xfetch(", re.IGNORECASE)
        assert len(got) == 3

    def test_matches_resume_where_the_last_ended(self) -> None:
        # Overlapping candidates: finditer takes "aaab" once, never the "aab" inside it.
        AnchorKit.both(rb"a{1,3}b", b"aaab aab ab b aaaab")

    def test_random_inputs(self) -> None:
        rng = random.Random(20261030)  # noqa: S311 - seeded test inputs, not a secret
        alphabet = b"fetch(axios.get) $`|\n \t\\eval"
        patterns = [rb"\bfetch\s*\(", rb"(?:\$\(\w*)|(?:\beval\b)", rb"(?:axi|get)os?\s*\."]
        for _ in range(300):
            data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
            for pattern in patterns:
                AnchorKit.both(pattern, data)


class TestThePlan:
    def test_an_anchored_pattern_is_planned(self) -> None:
        plan = AnchoredSearch.plan(re.compile(rb"\bfetch\s*\("))
        assert plan is not None and plan.rest is None
        assert [a.literal for a in plan.anchors] == [b"fetch"]

    def test_unanchored_alternatives_are_searched_apart(self) -> None:
        plan = AnchoredSearch.plan(re.compile(rb"(?:\bfetch\s*\()|(?:\$\(\w+)"))
        assert plan is not None and plan.rest is not None

    def test_nothing_to_anchor_on_is_no_plan(self) -> None:
        assert AnchoredSearch.plan(re.compile(rb"[a-z]+\d")) is None
        assert AnchoredSearch.plan(re.compile(rb"x*")) is None  # can match empty

    def test_too_many_candidates_falls_back_to_finditer(self) -> None:
        compiled = re.compile(rb"abc\d")
        data = b"abc" * 100_000 + b"abc1"
        plan = AnchoredSearch.plan(compiled)
        assert plan is not None
        assert AnchoredSearch._starts(plan.anchors, data, None) is None
        AnchorKit.both(rb"abc\d", data)
