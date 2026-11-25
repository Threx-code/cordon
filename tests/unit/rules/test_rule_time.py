"""S7: a crafted file that drives one rule's regex to super-linear time makes the scan incomplete,
never a pass (reviews/release-080/S7-RULE-BUDGET.md).

`CompiledMatch.matches` is the one door every rule's regex runs through (the architecture test
`test_rule_regexes_run_only_through_the_matcher`); its CPU budget is checked there.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.rules import pack as rule_pack
from cordon_scanner.rules.patterns import PatternCompiler
from support import requires_forked_workers


class RuleTimeKit:
    """A pack rule the validator accepts whose search is quadratic on a run of its first byte: each
    `a` is a place a match can start, and each attempt reads to the end of the run."""

    PATTERN = "a[a-z]*b"
    HOSTILE = "a" * 20_000
    PACK = """
pack: {id: test.slow, version: 1.0.0, license: Apache-2.0}
rules:
  - id: TEST.SLOW.001
    category: suspicious
    severity: high
    confidence: high
    title: A slow rule
    message: The slow rule matched.
    remediation: Remove it.
    match: {kind: regex, pattern: 'a[a-z]*b'}
    tests: {positive: ["aab"], negative: ["aa"]}
"""

    @staticmethod
    def compiled() -> rule_pack.CompiledMatch:
        from cordon_scanner.foundation.capabilities import MatchKind

        regex = PatternCompiler.validate_pattern(RuleTimeKit.PATTERN, rule_id="TEST.SLOW.001")
        return rule_pack.CompiledMatch(kind=MatchKind.REGEX, regex=regex, rule_id="TEST.SLOW.001")

    @staticmethod
    def scan(tmp_path: Path, text: str):
        pack = tmp_path / "pack.yaml"
        pack.write_text(RuleTimeKit.PACK, encoding="utf-8")
        root = tmp_path / "project"
        root.mkdir()
        (root / "notes.txt").write_text(text, encoding="utf-8")
        scanner = Scanner(replace(Config.default(), extra_rule_paths=(str(pack),)))
        return scanner.scan(root)


class TestARuleOverItsBudget:
    def test_the_validator_accepts_the_slow_pattern(self) -> None:
        # The static check is not enough on its own: this is the shape it lets through.
        PatternCompiler.validate_pattern(RuleTimeKit.PATTERN, rule_id="TEST.SLOW.001")

    def test_the_matcher_raises_past_the_budget(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_FLOOR", 0.02, raising=False)
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_PER_MB", 0.0, raising=False)
        compiled = RuleTimeKit.compiled()
        data = RuleTimeKit.HOSTILE.encode()
        with pytest.raises(TimeoutError, match=r"TEST\.SLOW\.001"):
            list(compiled.matches(compiled.regex, data))

    def test_a_fast_search_is_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        compiled = RuleTimeKit.compiled()
        data = b"x aab y aaab"
        assert [m.group() for m in compiled.matches(compiled.regex, data)] == [b"aab", b"aaab"]
        assert compiled.search(compiled.regex, b"zz") is None

    def test_the_callers_time_between_matches_is_not_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_FLOOR", 0.05, raising=False)
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_PER_MB", 0.0, raising=False)
        compiled = RuleTimeKit.compiled()
        found = 0
        for _ in compiled.matches(compiled.regex, b"ab " * 4):
            until = time.thread_time() + 0.03  # the caller's own work, on the same thread
            while time.thread_time() < until:
                pass
            found += 1
        assert found == 4

    def test_the_budget_is_not_configuration(self) -> None:
        # S10: a scanned tree's config cannot raise it; there is no setting to raise.
        import dataclasses

        names = {f.name for f in dataclasses.fields(Config.default().limits)}
        assert not any("rule" in name for name in names), names


class TestTheScanSaysSo:
    @requires_forked_workers
    def test_a_slow_rule_leaves_the_scan_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Before S7 this scan finished complete with no finding: a pass.
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_FLOOR", 0.05, raising=False)
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_PER_MB", 0.0, raising=False)
        result = RuleTimeKit.scan(tmp_path, RuleTimeKit.HOSTILE)
        timeouts = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TIMEOUT"]
        assert timeouts, [f.rule_id for f in result.findings]
        assert any("TEST.SLOW.001" in f.message for f in timeouts)
        assert not result.content_complete

    @requires_forked_workers
    def test_the_same_file_without_the_slow_shape_is_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_FLOOR", 0.05, raising=False)
        monkeypatch.setattr(rule_pack.CompiledMatch, "BUDGET_PER_MB", 0.0, raising=False)
        result = RuleTimeKit.scan(tmp_path, "z" * 20_000)
        assert not [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TIMEOUT"]
