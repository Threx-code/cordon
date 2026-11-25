"""A package-scope rule's own fact-vector samples run through the evaluation a scan uses, so a self-test and a real scan of the same shape agree."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.package_rules import PackageRules
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.rules.fact_terms import FactTerms
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.rules.tester import RuleTester

UNREACHED_SPAWNER = {
    "files": [{"reached": False, "places": [], "capabilities": ["spawn", "egress"]}],
    "package": {},
}
REACHED_SPAWNER = {
    "files": [{"reached": True, "places": ["install_entry"], "capabilities": ["spawn", "egress"]}],
    "package": {},
}


class Pack:
    @staticmethod
    def text(positive: list[dict], negative: list[dict]) -> str:
        return f"""
pack: {{id: test.vectors, version: 1.0.0, license: Apache-2.0}}
rules:
  - id: LEARNED.TEST.001
    category: suspicious
    severity: high
    confidence: medium
    title: A file nothing starts spawns and reaches the network
    message: A file nothing in the package runs starts a process and reaches the network.
    remediation: Remove the file.
    tests:
      facts_positive: {json.dumps(positive)}
      facts_negative: {json.dumps(negative)}
    match:
      kind: composite
      scope: package
      all:
        - file: {{where: unreached, capabilities: [spawn, egress]}}
"""

    @staticmethod
    def load(tmp_path: Path, positive: list[dict], negative: list[dict]):
        path = tmp_path / "pack.yaml"
        path.write_text(Pack.text(positive, negative), encoding="utf-8")
        return RuleLoader(require_tests=False).load_file(path)


class TestAFactVectorSelfTest:
    def test_a_pack_whose_vectors_agree_with_its_rule_passes(self, tmp_path: Path) -> None:
        pack = Pack.load(tmp_path, [UNREACHED_SPAWNER], [REACHED_SPAWNER])
        assert RuleTester.run(pack) == ()

    def test_a_positive_vector_the_rule_does_not_fire_on_fails_and_is_named(
        self, tmp_path: Path
    ) -> None:
        (failure,) = RuleTester.run(Pack.load(tmp_path, [REACHED_SPAWNER], [REACHED_SPAWNER]))
        assert (failure.rule_id, failure.kind) == ("LEARNED.TEST.001", "positive")

    def test_a_negative_vector_the_rule_fires_on_fails(self, tmp_path: Path) -> None:
        (failure,) = RuleTester.run(Pack.load(tmp_path, [UNREACHED_SPAWNER], [UNREACHED_SPAWNER]))
        assert failure.kind == "negative"

    def test_a_vector_that_is_not_a_record_is_refused_at_load(self, tmp_path: Path) -> None:
        from cordon_scanner.foundation.errors import RulePackError

        with pytest.raises(RulePackError, match="facts records"):
            Pack.load(tmp_path, ["not a record"], [])  # type: ignore[list-item]


class TestTheSelfTestAndAScanAgree:
    def test_the_vector_a_pack_passes_is_the_vector_a_real_scan_fires_on(
        self, tmp_path: Path
    ) -> None:
        """The same record, through the self-test's evaluation and through the scan's `FactTerms.of_facts` terms, gives the same answer."""
        pack = Pack.load(tmp_path, [UNREACHED_SPAWNER], [REACHED_SPAWNER])
        (compiled,) = pack.rules
        for record, fires in ((UNREACHED_SPAWNER, True), (REACHED_SPAWNER, False)):
            assert FactTerms.fires(compiled.match, FactTerms.of_facts(record).__contains__) is fires


class TestALearnedRuleFiresTheSameOnARecordAndOnAScan:
    """The pre-test judges a recorded facts record; the scan judges the package itself: for a learned rule they give one answer."""

    HOOK_RECORD: ClassVar[dict] = {"files": [], "package": {"hooks": [{"kind": "postinstall"}]}}
    PLAIN_RECORD: ClassVar[dict] = {"files": [], "package": {}}

    @staticmethod
    def pack(tmp_path: Path) -> Path:
        path = tmp_path / "pack.yaml"
        path.write_text(
            f"""
pack: {{id: test.same, version: 1.0.0, license: Apache-2.0}}
rules:
  - id: LEARNED.TEST.002
    category: suspicious
    severity: high
    confidence: medium
    title: A package runs a script when it is installed
    message: The package declares a script that runs when it is installed.
    remediation: Remove the script.
    tests:
      facts_positive: {json.dumps([TestALearnedRuleFiresTheSameOnARecordAndOnAScan.HOOK_RECORD])}
      facts_negative: {json.dumps([TestALearnedRuleFiresTheSameOnARecordAndOnAScan.PLAIN_RECORD])}
    match:
      kind: composite
      scope: package
      all:
        - hook: postinstall
""",
            encoding="utf-8",
        )
        return path

    @staticmethod
    def scan_fires(tmp_path: Path, pack: Path, scripts: dict[str, str]) -> set[str]:
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts}), encoding="utf-8"
        )
        (root / "setup.js").write_text("console.log('x');\n", encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False, extra_rule_paths=(str(pack),))
        return {f.rule_id for f in Scanner(config).scan(root).findings} & {"LEARNED.TEST.002"}

    def test_a_package_with_the_hook_fires_on_the_record_and_on_the_scan(
        self, tmp_path: Path
    ) -> None:
        pack = self.pack(tmp_path)
        rules = RuleSet([RuleLoader(require_tests=False).load_file(pack)])
        assert PackageRules.fires(rules, self.HOOK_RECORD) == ["LEARNED.TEST.002"]
        assert self.scan_fires(tmp_path, pack, {"postinstall": "node setup.js"}) == {
            "LEARNED.TEST.002"
        }

    def test_a_package_without_it_fires_on_neither(self, tmp_path: Path) -> None:
        pack = self.pack(tmp_path)
        rules = RuleSet([RuleLoader(require_tests=False).load_file(pack)])
        assert PackageRules.fires(rules, self.PLAIN_RECORD) == []
        assert self.scan_fires(tmp_path, pack, {"test": "node setup.js"}) == set()
