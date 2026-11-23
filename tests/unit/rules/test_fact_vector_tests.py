"""A package-scope rule's own fact-vector samples run through the evaluation a scan uses, so a self-test and a real scan of the same shape agree."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner.rules.fact_terms import FactTerms
from cordon_scanner.rules.loader import RuleLoader
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
