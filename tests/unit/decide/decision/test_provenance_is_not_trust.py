"""A good provenance, a valid signature or a verified publisher never turns a malicious finding into a pass or excuses a capability over its ceiling.

The decision keeps its dimensions apart: what was found, how it was built, what it may do, and what the organisation's policy says. A signed package that is known malware is blocked at every level of
provenance, verified or not; an agent from a verified publisher that declares a capability its policy forbids is sent to review, and one that declares nothing forbidden is not.
"""

from __future__ import annotations

import pytest
from test_decider import F

from cordon_scanner.decide.decision.evidence import EvidenceSet, IntelMatch, Provenance

MALWARE = IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z")
FORBID_DELEGATION = {
    "id": "agents-may-not-delegate",
    "tier": "deny",
    "then": "review",
    "when": {"agent.capabilities": "delegation"},
}


class Dimensions:
    @staticmethod
    def agent(*declared: str):
        return F.artifact(
            kind="agent", subject_id="agent:acme/builder", capabilities=declared or None
        )


class TestASignedMaliciousPackageIsStillMalicious:
    @pytest.mark.parametrize("level", [0, 1, 2, 3, 4])
    @pytest.mark.parametrize("verified", [True, False])
    def test_known_malware_is_blocked_at_every_provenance_level(
        self, level: int, verified: bool
    ) -> None:
        evidence = EvidenceSet(
            intel=(MALWARE,),
            provenance=Provenance(level, "sigstore:acme/release", verified=verified),
        )
        decision = F.decide(evidence)
        assert decision.state == "BLOCK" and decision.reason_codes == ("R100",)

    def test_the_provenance_changes_nothing_in_the_answer(self) -> None:
        bare = F.decide(EvidenceSet(intel=(MALWARE,)))
        signed = F.decide(
            EvidenceSet(intel=(MALWARE,), provenance=Provenance(4, "sigstore:acme/release"))
        )
        assert (bare.state, bare.reason_codes) == (signed.state, signed.reason_codes)

    def test_a_malicious_finding_is_blocked_whatever_the_provenance(self) -> None:
        finding = F.finding(category="malicious", severity="critical", confidence="high")
        for provenance in (
            None,
            Provenance(0, None, verified=False),
            Provenance(4, "sigstore:acme/release"),
        ):
            assert (
                F.decide(EvidenceSet(findings=(finding,), provenance=provenance)).state == "BLOCK"
            )

    def test_a_publisher_known_for_a_long_time_does_not_excuse_it_either(self) -> None:
        old = Provenance(4, "sigstore:acme/release", publisher_first_seen="2015-01-01T00:00:00Z")
        assert F.decide(EvidenceSet(intel=(MALWARE,), provenance=old)).state == "BLOCK"


class TestAVerifiedAgentOverItsCeiling:
    def test_it_is_sent_to_review(self) -> None:
        policy = F.policy(rules=[FORBID_DELEGATION])
        evidence = EvidenceSet(provenance=Provenance(4, "sigstore:acme/release"))
        decision = F.decide(evidence, policy=policy, artifact=Dimensions.agent("delegation"))
        assert decision.state == "REVIEW"

    def test_the_same_agent_declaring_nothing_forbidden_is_not(self) -> None:
        policy = F.policy(rules=[FORBID_DELEGATION])
        evidence = EvidenceSet(provenance=Provenance(4, "sigstore:acme/release"))
        decision = F.decide(evidence, policy=policy, artifact=Dimensions.agent("documents", "apis"))
        assert decision.state != "REVIEW" and decision.state != "BLOCK"

    def test_verifying_the_publisher_does_not_lift_the_review(self) -> None:
        policy = F.policy(rules=[FORBID_DELEGATION])
        unsigned = F.decide(EvidenceSet(), policy=policy, artifact=Dimensions.agent("delegation"))
        signed = F.decide(
            EvidenceSet(provenance=Provenance(4, "sigstore:acme/release")),
            policy=policy,
            artifact=Dimensions.agent("delegation"),
        )
        assert unsigned.state == signed.state == "REVIEW"

    def test_known_malware_in_it_is_still_a_block_not_a_review(self) -> None:
        policy = F.policy(rules=[FORBID_DELEGATION])
        evidence = EvidenceSet(intel=(MALWARE,), provenance=Provenance(4, "sigstore:acme/release"))
        assert (
            F.decide(evidence, policy=policy, artifact=Dimensions.agent("delegation")).state
            == "BLOCK"
        )
