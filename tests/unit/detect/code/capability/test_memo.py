"""The capability detector's pattern-tier hits kept per distinct whole file
(`detect/code/capability/memo`)."""

from __future__ import annotations

import dataclasses
from typing import Any

from cordon_scanner.detect.code.capability.memo import CapabilityMemo
from cordon_scanner.foundation.content import FileContent


class Matcher:
    """A stand-in for the detector: counts how often the pattern tier runs."""

    def __init__(self) -> None:
        self.runs = 0

    def _match_capabilities(
        self, content: FileContent, candidates: Any, language: Any
    ) -> list[Any]:
        self.runs += 1
        return [("hit", len(content.raw), language)]


class TestCapabilityMemo:
    RULES = (object(), object())
    RAW = b"import os\n" + b"x = 1\n" * 1000

    def test_the_same_file_and_rules_are_matched_once(self) -> None:
        matcher = Matcher()
        a = FileContent.from_bytes("a/one.py", self.RAW)
        b = FileContent.from_bytes("b/copy.py", self.RAW)
        first = CapabilityMemo.hits(matcher, a, self.RULES, "python")
        assert CapabilityMemo.hits(matcher, b, self.RULES, "python") == first
        assert matcher.runs == 1

    def test_other_rules_or_language_are_matched_again(self) -> None:
        matcher = Matcher()
        content = FileContent.from_bytes("a/two.py", self.RAW + b"# two\n")
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        CapabilityMemo.hits(matcher, content, (object(),), "python")
        CapabilityMemo.hits(matcher, content, self.RULES, "javascript")
        assert matcher.runs == 3

    def test_a_cut_short_file_is_matched_every_time(self) -> None:
        matcher = Matcher()
        content = dataclasses.replace(
            FileContent.from_bytes("a/three.py", self.RAW + b"# three\n"), truncated=True
        )
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        CapabilityMemo.hits(matcher, content, self.RULES, "python")
        assert matcher.runs == 2
