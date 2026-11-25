"""No contract and no decision returns one numeric trust score: severity, confidence, provenance, permissions and policy stay separate.

The answer a client reads is a state and the reasons for it. A single number would let a good provenance average a malicious finding away, so none of the records a client receives carries one at its top
level, and a real decision, however it was reached, holds no value named like a score, a rating, a grade or a trust level at any depth.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from test_decider import F

from cordon_scanner.decide.decision.evidence import EvidenceSet, IntelMatch, Provenance
from support import ROOT

SCHEMAS = sorted((ROOT / "src" / "cordon_scanner" / "contracts" / "schemas").glob("*.json"))
SCORE_WORDS = re.compile(r"score|rating|grade|trust_?level|trust_?value", re.IGNORECASE)
NUMERIC = {"number", "integer"}


class Walk:
    @staticmethod
    def kinds(spec: dict[str, Any]) -> set[str]:
        """The JSON types a property may take (a schema writes one, or a list of them)."""
        kind = spec.get("type")
        return set(kind) if isinstance(kind, list) else {kind} if isinstance(kind, str) else set()

    @staticmethod
    def names(value: Any, path: str = "") -> list[str]:
        """Every key at any depth, with the path to it."""
        found: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                found.append(f"{path}/{key}")
                found += Walk.names(item, f"{path}/{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                found += Walk.names(item, f"{path}[{index}]")
        return found


class TestTheContracts:
    @pytest.mark.parametrize("schema", SCHEMAS, ids=[path.stem for path in SCHEMAS])
    def test_no_record_carries_a_number_at_its_top_level(self, schema: Any) -> None:
        properties = json.loads(schema.read_text(encoding="utf-8")).get("properties", {})
        numbers = [
            name
            for name, spec in properties.items()
            if isinstance(spec, dict) and NUMERIC & Walk.kinds(spec)
        ]
        assert numbers == []

    @pytest.mark.parametrize("schema", SCHEMAS, ids=[path.stem for path in SCHEMAS])
    def test_no_top_level_property_is_named_like_a_score(self, schema: Any) -> None:
        properties = json.loads(schema.read_text(encoding="utf-8")).get("properties", {})
        assert [name for name in properties if SCORE_WORDS.search(name)] == []


class TestADecision:
    @pytest.mark.parametrize(
        "evidence",
        [
            EvidenceSet(),
            EvidenceSet(
                intel=(IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z"),),
                provenance=Provenance(4, "sigstore:acme/release"),
            ),
            EvidenceSet(
                provenance=Provenance(2, "sigstore:acme/release"),
                findings=(F.finding(severity="high", confidence="high"),),
            ),
        ],
        ids=["nothing found", "signed malware", "a high finding with provenance"],
    )
    def test_holds_no_value_named_like_a_score_at_any_depth(self, evidence: EvidenceSet) -> None:
        record = F.decide(evidence).to_json()
        assert [
            name for name in Walk.names(record) if SCORE_WORDS.search(name.rsplit("/", 1)[-1])
        ] == []

    def test_its_answer_is_a_state_from_a_closed_list(self) -> None:
        assert F.decide(EvidenceSet()).state in {
            "ALLOW",
            "ALLOW_WITH_CONDITIONS",
            "REVIEW",
            "BLOCK",
        }

    def test_the_check_finds_a_score_where_one_is_written(self) -> None:
        assert [
            n
            for n in Walk.names({"explanation": {"trust_score": 0.9}})
            if SCORE_WORDS.search(n.rsplit("/", 1)[-1])
        ] == ["/explanation/trust_score"]
