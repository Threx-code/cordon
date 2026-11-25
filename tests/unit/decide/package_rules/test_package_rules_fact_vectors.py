"""A pack's fact-vector self-test and a real scan of the same shape agree, because both are judged by the one evaluator.

A package-scope rule is judged on terms: by a scan, from the findings and the places of the files it read, and by a self-test, from a recorded facts record. `PackageRules.satisfied` is the only place the rule's
`all`, `any` and `unless` are applied; `PackageRules.fires` hands it the terms of a facts record. For each shape of package below, the rules a real scan fires are the rules the facts record of that scan fires.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_package_rules import RULE, RULE_BY_REACH, RULE_BY_STRING, PackageKit

from cordon_scanner.decide.package_rules import PackageRules
from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.rules.loader import RuleLoader, RuleSet

ORPHAN = "module.exports = (a, b) => a + b;\n"
LOADED = "const helper = require('./lib/helper');\nmodule.exports = helper;\n"
NAMED = "module.exports = ['lib/helper.js'];\n"
UNLESS = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.004").replace(
    "        - file: {where: unreached, capabilities: [spawn, egress]}\n",
    "        - file: {where: unreached, capabilities: [spawn, egress]}\n      unless:\n        - file: {where: any, capabilities: [credential]}\n",
)
ANY = RULE.replace("LEARNED.TEST.001", "LEARNED.TEST.005").replace(
    "      all:\n        - file: {where: unreached, capabilities: [spawn, egress]}\n",
    "      any:\n        - file: {where: unreached, capabilities: [spawn, egress]}\n        - file: {where: unreached, capabilities: [execute, egress]}\n",
)


class Shapes:
    @staticmethod
    def scan(tmp_path: Path, index: str, rule: str) -> Any:
        return PackageKit.scan(tmp_path, index=index, rule=rule)

    @staticmethod
    def ruleset(tmp_path: Path, rule: str) -> RuleSet:
        pack = tmp_path / "judged.yaml"
        pack.write_text(rule, encoding="utf-8")
        return RuleSet([RuleLoader().load_file(pack)])

    @staticmethod
    def fired_by_the_scan(result: Any) -> set[str]:
        return {f.rule_id for f in result.findings if f.rule_id.startswith("LEARNED.")}

    @staticmethod
    def fired_by_the_record(rules: RuleSet, result: Any) -> set[str]:
        return set(PackageRules.fires(rules, ScanFacts.of(result)))


class TestAFactVectorAndARealScanAgree:
    @pytest.mark.parametrize(
        ("name", "index", "rule"),
        [
            ("an orphan that spawns and egresses", ORPHAN, RULE),
            ("the same file loaded by the entry point", LOADED, RULE),
            ("a rule on how the orphan is reached", ORPHAN, RULE_BY_REACH),
            ("a path string names the file", NAMED, RULE_BY_STRING),
            ("a string names nothing", ORPHAN, RULE_BY_STRING),
            ("an unless term that does not hold", ORPHAN, UNLESS),
            ("an any term where one holds", ORPHAN, ANY),
        ],
    )
    def test_the_rules_a_scan_fires_are_the_rules_its_facts_record_fires(
        self, tmp_path: Path, name: str, index: str, rule: str
    ) -> None:
        result = Shapes.scan(tmp_path, index, rule)
        rules = Shapes.ruleset(tmp_path, rule)
        assert Shapes.fired_by_the_record(rules, result) == Shapes.fired_by_the_scan(result), name

    def test_a_shape_that_fires_and_a_shape_that_does_not_are_both_present_in_the_cases(
        self, tmp_path: Path
    ) -> None:
        fires = Shapes.scan(tmp_path, ORPHAN, RULE)
        (tmp_path / "again").mkdir()
        quiet = Shapes.scan(tmp_path / "again", LOADED, RULE)
        assert Shapes.fired_by_the_scan(fires) and not Shapes.fired_by_the_scan(quiet)

    def test_a_hand_written_fact_vector_is_judged_the_same_way(self, tmp_path: Path) -> None:
        rules = Shapes.ruleset(tmp_path, RULE)
        vector = {
            "files": [
                {
                    "reached": False,
                    "places": [],
                    "capabilities": ["egress", "spawn"],
                    "reach": "unreached",
                }
            ],
            "package": {},
        }
        assert PackageRules.fires(rules, vector) == ["LEARNED.TEST.001"]
        vector["files"][0]["capabilities"] = ["egress"]
        assert PackageRules.fires(rules, vector) == []

    def test_there_is_one_judgement_of_a_rule(self) -> None:
        import inspect

        decide = inspect.getsource(PackageRules.decide)
        fires = inspect.getsource(PackageRules.fires)
        assert "PackageRules.satisfied" in decide and "PackageRules.satisfied" in fires
        assert "all_of" not in decide and "unless" not in decide
