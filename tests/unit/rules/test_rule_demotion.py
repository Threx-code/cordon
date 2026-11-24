"""A delivered rule that fires on a bundled benign fixture is run as a warning, and the scan's result counts it.

When a delivered pack loads, its text rules are tried on a few invented, ordinary files that ship with the scanner. A rule that matches one is wrong about ordinary code: it is demoted to warn at
once (low severity and confidence, the policy category, a message that says so) and the scan's result names it with the reason. A rule that matches none is left as it was. The caller's own record
(the device's circuit breaker) can demote rules by id the same way.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.benign_fixtures import BenignFixtures
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader
from kits.delivered_sets import GOOD, Isolated, Sets

FIRING = "LEARNED.EDGE.5"


class Demoted(Isolated):
    @staticmethod
    def install() -> None:
        """One pack, two rules: one on `console.log` (every benign program has it), one on a word nothing benign holds."""
        quiet = Sets.pack("quiet", GOOD, "zzquiet_call", "zzquiet_call(x)").rstrip("\n")
        loud = (
            f"\n  - id: {FIRING}\n    category: suspicious\n    severity: high\n    confidence: medium\n    title: A rule on ordinary code\n"
            "    message: It fires on a console log.\n    remediation: Fix it.\n    match:\n      kind: regex\n      pattern: 'console\\.log'\n"
            '    tests:\n      positive:\n        - "console.log(x)"\n      negative:\n        - "safe_call(x)"\n'
        )
        name = "rulepack-zmix.yaml"
        FeedRules.install(Sets.rules([Sets.entry(name)], {name: quiet + loud}))

    @staticmethod
    def rules() -> dict[str, Any]:
        return {
            c.rule.id: c.rule
            for p in FeedPacks.packs(RuleLoader(), set(), shadow=False)
            for c in p.rules
        }


class TestAtLoad(Demoted):
    def test_the_fixtures_are_ordinary_and_invented(self) -> None:
        text = b"\n".join(BenignFixtures.files())
        assert (
            b"console.log" in text
            and len(BenignFixtures.files())
            == len(BenignFixtures.PROGRAMS) + BenignFixtures.CORPUS_FILES
        )

    def test_a_rule_that_fires_on_a_benign_fixture_is_demoted_to_warn(self) -> None:
        self.install()
        rule = self.rules()[FIRING]
        assert (rule.severity, rule.category) == (Severity.LOW, Category.POLICY)
        assert rule.message.startswith("[demoted to warn: it fired on a bundled benign fixture]")

    def test_a_rule_that_fires_on_none_is_left_as_it_was(self) -> None:
        self.install()
        rule = self.rules()[GOOD]
        assert rule.severity is Severity.HIGH and not rule.message.startswith("[demoted")

    def test_the_demoted_rules_are_listed_with_the_reason(self) -> None:
        self.install()
        assert FeedPacks.demoted(RuleLoader(), set()) == (
            (FIRING, "it fired on a bundled benign fixture"),
        )


class TestTheCallersRecord(Demoted):
    def test_a_rule_named_by_the_caller_is_demoted_with_its_reason(self) -> None:
        self.install()
        packs = FeedPacks.packs(
            RuleLoader(),
            set(),
            shadow=False,
            demote={GOOD: "it blocked 3 of 150 local scans in 24 hours"},
        )
        rules = {c.rule.id: c.rule for p in packs for c in p.rules}
        assert rules[GOOD].severity is Severity.LOW
        assert "blocked 3 of 150" in rules[GOOD].message


class TestTheScanResult(Demoted):
    def test_a_scan_names_the_demoted_rule_in_its_stats_json_and_sarif(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.report.base import ReportOptions

        self.install()
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0"}), encoding="utf-8"
        )
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            tmp_path
        )
        assert list(result.stats.rules_demoted) == [FIRING]
        options = ReportOptions(color=False)
        document: Any = json.loads(b"".join(Registry().reporter("json").render(result, options)))
        assert list(document["stats"]["rules_demoted"]) == [FIRING]
        sarif: Any = json.loads(b"".join(Registry().reporter("sarif").render(result, options)))
        assert sarif["runs"][0]["properties"]["ruleDemotions"]["count"] == 1
