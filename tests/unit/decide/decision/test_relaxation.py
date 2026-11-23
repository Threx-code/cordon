"""A relaxed fail-closed default is part of the decision's record (invariant I4, row BP-0-8).

A policy may let one environment treat a shortfall (an unresolved subject, an incomplete scan, a content gap, stale
intelligence, an expired bundle) as a warning or a review instead of a block. What it lets through must be readable from the
decision itself, and it must be inside the signed bytes: a stored decision then says not only that it allowed, but that it
allowed because this environment relaxes that default.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.schema_check import SchemaChecker
from cordon_scanner.contracts.schemas import ContractSchemas
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import (
    ArtifactRef,
    Context,
    EvidenceSet,
    GapFact,
    IntelMatch,
)
from cordon_scanner.decide.decision.outcome import Decision, Relaxation
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import DecisionError

DIGEST = ArtifactDigests.of_bytes(b"the artifact")
CLOCK = datetime(2026, 11, 17, 8, 0, 30, tzinfo=UTC)


class Kit:
    @staticmethod
    def decide(defaults: dict, evidence: EvidenceSet, environment: str = "dev") -> Decision:
        policy = PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/relaxed",
                    "version": 3,
                    "scope": ["acme"],
                    "rules": [],
                    "defaults": copy.deepcopy(defaults),
                }
            )
        )
        artifact = ArtifactRef(
            kind="package",
            subject_id="pkg:npm/left-pad",
            digest=DIGEST,
            ecosystem="npm",
            released_at="2026-06-01T00:00:00Z",
        )
        context = Context(point="ci_gate", environment=environment, scope_path=("acme",))
        return Decider.decide(artifact, context, policy, evidence, CLOCK)


class TestTheRecordNamesTheRelaxation:
    def test_an_incomplete_scan_let_through_by_a_relaxed_environment(self) -> None:
        defaults = {"on_incomplete": {"*": "block", "dev": "review"}}
        decision = Kit.decide(defaults, EvidenceSet(complete=False), "dev")
        assert decision.state == "REVIEW"
        assert decision.relaxations == (Relaxation("R204", "on_incomplete", "review", "dev"),)

    def test_an_unresolved_subject_let_through_as_a_warning(self) -> None:
        decision = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        assert decision.state == "ALLOW"
        assert decision.relaxations == (Relaxation("R203", "unresolved", "warn", "dev"),)

    def test_a_content_gap_let_through_as_a_warning(self) -> None:
        evidence = EvidenceSet(gaps=(GapFact("OPERATIONAL.FILE.TRUNCATED", "a.js"),))
        decision = Kit.decide({"on_gaps": "warn"}, evidence)
        assert decision.relaxations == (Relaxation("R204", "on_gaps", "warn", "dev"),)

    def test_every_relaxed_shortfall_is_listed_once_in_a_fixed_order(self) -> None:
        defaults = {"unresolved": "warn", "on_incomplete": "review", "on_gaps": "warn"}
        evidence = EvidenceSet(
            unresolved=True,
            complete=False,
            gaps=(
                GapFact("OPERATIONAL.FILE.TRUNCATED", "a.js"),
                GapFact("OPERATIONAL.FILE.TRUNCATED", "b.js"),
            ),
        )
        decision = Kit.decide(defaults, evidence)
        assert decision.relaxations == (
            Relaxation("R203", "unresolved", "warn", "dev"),
            Relaxation("R204", "on_gaps", "warn", "dev"),
            Relaxation("R204", "on_incomplete", "review", "dev"),
        )
        assert decision.state == "REVIEW"


class TestNothingIsRecordedWhereNothingWasRelaxed:
    def test_the_default_block_records_no_relaxation_and_blocks(self) -> None:
        decision = Kit.decide({}, EvidenceSet(complete=False))
        assert decision.state == "BLOCK"
        assert decision.relaxations is None
        assert "relaxations" not in decision.to_json()

    def test_an_environment_the_policy_does_not_relax_records_none(self) -> None:
        defaults = {"on_incomplete": {"*": "block", "dev": "review"}}
        decision = Kit.decide(defaults, EvidenceSet(complete=False), "production")
        assert decision.state == "BLOCK" and decision.relaxations is None

    def test_a_complete_call_under_a_relaxed_policy_records_none(self) -> None:
        decision = Kit.decide({"on_incomplete": "warn", "unresolved": "warn"}, EvidenceSet())
        assert decision.relaxations is None

    def test_a_hard_stop_is_never_relaxed_and_records_none(self) -> None:
        malware = IntelMatch(
            kind="known_malware", id="MAL-1", source="osv", first_seen="2026-11-01T00:00:00Z"
        )
        evidence = EvidenceSet(complete=False, intel=(malware,))
        decision = Kit.decide({"on_incomplete": "warn"}, evidence)
        assert decision.state == "BLOCK" and decision.relaxations is None


class TestTheRecordIsPartOfTheContract:
    def test_the_decision_with_a_relaxation_is_a_valid_decision_v1_predicate(self) -> None:
        decision = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        document = decision.to_json()
        assert SchemaChecker.errors(ContractSchemas.load("decision-v1"), document) == []
        assert document["relaxations"] == [
            {"code": "R203", "setting": "unresolved", "level": "warn", "environment": "dev"}
        ]

    def test_a_relaxation_that_names_a_setting_the_policy_does_not_have_is_refused(self) -> None:
        document = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True)).to_json()
        document["relaxations"][0]["setting"] = "on_anything"
        assert SchemaChecker.errors(ContractSchemas.load("decision-v1"), document) != []

    def test_it_survives_a_round_trip_through_json(self) -> None:
        decision = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        assert Decision.from_json(decision.to_json()) == decision

    def test_it_is_inside_the_bytes_a_signature_covers(self) -> None:
        decision = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        bare = replace(decision, relaxations=None)
        assert decision.canonical_bytes() != bare.canonical_bytes()

    def test_the_same_inputs_give_the_same_bytes(self) -> None:
        one = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        two = Kit.decide({"unresolved": "warn"}, EvidenceSet(unresolved=True))
        assert one.canonical_bytes() == two.canonical_bytes()

    @pytest.mark.parametrize("level", ["block", "allow", ""])
    def test_a_relaxation_is_only_a_warn_or_a_review(self, level: str) -> None:
        with pytest.raises(DecisionError):
            Relaxation("R203", "unresolved", level, "dev")

    def test_a_relaxation_names_a_registered_reason_code(self) -> None:
        with pytest.raises(DecisionError):
            Relaxation("R999", "unresolved", "warn", "dev")
