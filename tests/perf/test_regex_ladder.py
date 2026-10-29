"""Every pattern the static shape check flags is timed, and its list must say what the timing says.

The unit suite (tests/unit/repository/test_regex_scaling.py) reads each pattern's shape and requires
every flagged one to be listed in `kits.regexkit.Listed`. This tier confirms the lists with the timing
ladder (`kits.regexkit.Ladder`): an open pattern or a kept specification must still measure
superlinear or slow, and a pattern listed as linear must measure linear. The ladder first measures known
superlinear and linear patterns of its own, so a broken measure fails here rather than passing.

Marked `perf`: it runs in the prepush performance step, a few minutes, four patterns at a time.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import pytest

from kits.regexkit import Found, Ladder, Listed, Sources

pytestmark = pytest.mark.perf


class Known:
    """Patterns whose timing is known, for the ladder to measure first."""

    @staticmethod
    def found(label: str, pattern: str, mode: str) -> Found:
        return Found(label, re.compile(pattern), frozenset({mode}), True)

    SUPERLINEAR = (
        ("blanks either side of an optional dash", r"(?m)^([ \t]*)-?[ \t]*run:", "search"),
        ("a lazy value before trailing blanks", r"^\s*-\s+(.+?)\s*$", "match"),
        ("a class of blanks before blanks", r"(?i)\s*(?:(?:ls|cat)\b[^;&|<>`$]*)\s*", "fullmatch"),
        ("a long bounded repeat from every start", r"[^\n]{1,2000}?(?:[.!?](?!\w)|\n|$)", "search"),
    )
    LINEAR = (
        ("possessive indentation", r"(?m)^([ \t]*+)-?[ \t]*run:", "search"),
        ("a value up to its last non-blank", r"^\s*-\s+(.*\S|[^\S\n])\s*$", "match"),
        ("a bounded run", r"\b[0-9a-f]{32}\b", "search"),
    )


class TestTheLadder:
    def test_it_finds_known_superlinear_patterns(self) -> None:
        missed = [
            label
            for label, pattern, mode in Known.SUPERLINEAR
            if Ladder.check(Known.found(label, pattern, mode)) is None
        ]
        assert not missed

    def test_it_passes_known_linear_patterns(self) -> None:
        flagged = {
            label: why
            for label, pattern, mode in Known.LINEAR
            if (why := Ladder.check(Known.found(label, pattern, mode)))
        }
        assert not flagged


class TestTheLists:
    def test_each_listed_pattern_measures_as_its_list_says(self) -> None:
        by_label = Sources.by_label()
        slow = set(Listed.OPEN) | set(Listed.SPECIFICATIONS)
        labels = sorted(slow | set(Listed.LINEAR))
        with ThreadPoolExecutor(max_workers=4) as pool:
            verdicts = dict(
                zip(
                    labels,
                    pool.map(lambda label: Ladder.check(by_label[label]), labels),
                    strict=True,
                )
            )
        print("\n".join(f"{label}: {verdicts[label] or 'linear'}" for label in labels))
        no_longer = sorted(label for label in slow if verdicts[label] is None)
        not_linear = {label: verdicts[label] for label in Listed.LINEAR if verdicts[label]}
        assert not no_longer, "linear now: remove it from Listed.OPEN or Listed.SPECIFICATIONS"
        assert not not_linear, "superlinear or slow: it cannot be listed as linear"
