"""A block by a learned rule counts as content, and a rule prefix nobody classified fails the build."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
from bench.cdi.gate import Gate
from bench.cdi.rule_prefixes import CLASSES, CONTENT, RulePrefixes

RULE_ID = re.compile(r"\"([A-Z][A-Z0-9_]{2,15}\.[A-Z][A-Z0-9_.]{2,}[0-9]{3})\"")


class Kit:
    @staticmethod
    def blocked(rule: str, severity: str = "high") -> dict:
        return {"exit": 1, "findings": [[rule, severity, "high", "malicious"]]}

    @staticmethod
    def scanner_rule_ids() -> list[str]:
        """Every rule id the scanner's source writes down and every id in its bundled packs."""
        from cordon_scanner.rules.loader import RuleLoader

        spec = importlib.util.find_spec("cordon_scanner")
        assert spec is not None and spec.submodule_search_locations
        root = Path(next(iter(spec.submodule_search_locations)))
        ids = [
            m
            for path in root.rglob("*.py")
            for m in RULE_ID.findall(path.read_text(encoding="utf-8"))
        ]
        loader = RuleLoader(require_tests=False, strict_baseline=False)
        ids += [
            rule.id
            for pack in loader.load_dir(RuleLoader.builtin_pack_dir())
            for rule in pack.rules
        ]
        return ids


class TestALearnedRuleIsContent:
    def test_a_benign_unit_blocked_by_a_learned_rule_is_a_malware_class_block(self) -> None:
        assert Gate.malware_class_block(Kit.blocked("LEARNED.NPM.001")) is True

    def test_a_learned_rule_is_classed_as_content(self) -> None:
        assert RulePrefixes.classify("LEARNED.SKILLS.012") == CONTENT == CLASSES["LEARNED."]

    def test_a_secret_a_policy_and_a_vulnerability_block_are_reported_apart(self) -> None:
        for rule in (
            "SECRET.AWS.ACCESS_KEY.001",
            "POLICY.PACKAGE.EXAMPLE.001",
            "VULNERABLE.NPM.001",
        ):
            assert Gate.malware_class_block(Kit.blocked(rule)) is False, rule

    def test_a_block_by_a_prefix_nobody_has_classified_still_counts(self) -> None:
        assert Gate.malware_class_block(Kit.blocked("BRANDNEW.THING.001")) is True
        assert RulePrefixes.classify("BRANDNEW.THING.001") == CONTENT

    def test_a_low_finding_never_makes_a_block(self) -> None:
        assert Gate.malware_class_block(Kit.blocked("LEARNED.NPM.001", "low")) is False


class TestANewPrefixFailsTheBuildUntilItIsClassified:
    def test_the_finder_names_a_prefix_that_is_not_in_the_list(self) -> None:
        assert RulePrefixes.unclassified(
            ["MALWARE.A.001", "LEARNED.X.001", "NEWFAMILY.A.001", "NEWFAMILY.B.002"]
        ) == ["NEWFAMILY."]

    def test_every_prefix_the_scanner_can_emit_is_classified(self) -> None:
        ids = Kit.scanner_rule_ids()
        assert len(ids) > 300, (
            "the scan of the scanner's rule ids found almost nothing: the test is not looking"
        )
        assert RulePrefixes.unclassified(ids) == []

    @pytest.mark.parametrize("prefix", sorted(CLASSES))
    def test_every_class_named_is_one_of_the_four(self, prefix: str) -> None:
        assert CLASSES[prefix] in {"content", "policy", "advisory", "operational"}
