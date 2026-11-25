"""The artifact, context and evidence types: closed vocabularies, strict fields, a canonical evidence digest."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.evidence import (
    Approval,
    ArtifactRef,
    Context,
    EvidenceSet,
    FindingFact,
    GapFact,
    IntelMatch,
    Provenance,
)
from cordon_scanner.decide.decision.records import DecisionError

DIGEST = ArtifactDigests.of_bytes(b"example")
CLOCK = datetime(2026, 11, 17, 8, 0, tzinfo=UTC)


class Facts:
    @staticmethod
    def finding(
        rule: str = "SUSPECT.X.001", path: str = "a.js", line: int | None = 1, **kw
    ) -> FindingFact:
        return FindingFact(
            rule,
            kw.get("severity", "high"),
            kw.get("confidence", "medium"),
            kw.get("category", "suspicious"),
            path=path,
            line=line,
        )


finding = Facts.finding


class TestTheVocabulariesAreClosed:
    @pytest.mark.parametrize(
        "make",
        [
            lambda: ArtifactRef("plugin", "pkg:npm/x"),
            lambda: ArtifactRef("package", "pkg:npm/x", digest="md5:abc"),
            lambda: ArtifactRef("package", "pkg:npm/x", released_at="yesterday"),
            lambda: Context("telepathy", "dev"),
            lambda: Context("cli", "dev", relation="cousin"),
            lambda: Context("cli", "dev", intel_age_s=-1),
            lambda: FindingFact("X.1", "severe", "low", "policy"),
            lambda: FindingFact("X.1", "high", "certain", "policy"),
            lambda: FindingFact("X.1", "high", "low", "dubious"),
            lambda: IntelMatch("rumour", "I-1", "osv", "2026-11-17T08:00:00Z"),
            lambda: Provenance(slsa_level=9),
            lambda: Approval("a1", "wave", "2027-01-01T00:00:00Z"),
            lambda: Approval("a1", "approve", "2027-01-01T00:00:00Z", digests=("nope",)),
            lambda: Approval("a1", "exception", "2027-01-01T00:00:00Z", outcome="DENY"),
            lambda: Approval("a1", "approve", "2027-01-01T00:00:00Z", outcome="ALLOW"),
            lambda: Approval("a1", "exception", "2027-01-01T00:00:00Z", reason_codes="R400"),
        ],
    )
    def test_a_value_outside_its_vocabulary_is_refused(self, make) -> None:
        with pytest.raises(DecisionError):
            make()


class TestApprovals:
    def approval(self, **kw) -> Approval:
        return Approval(
            "a1",
            "approve",
            kw.pop("expires_at", "2026-12-01T00:00:00Z"),
            digests=kw.pop("digests", (DIGEST,)),
            **kw,
        )

    def test_active_until_it_expires_and_never_once_revoked(self) -> None:
        assert self.approval().active(CLOCK)
        assert not self.approval(expires_at="2026-11-17T08:00:00Z").active(CLOCK)
        assert not self.approval(revoked=True).active(CLOCK)

    def test_it_covers_only_the_digests_it_lists_in_its_scope_or_below(self) -> None:
        a = self.approval(scope_path=("acme", "payments"))
        assert a.covers(DIGEST, ("acme", "payments", "ledger"))
        assert not a.covers(DIGEST, ("acme", "platform"))
        assert not a.covers(ArtifactDigests.of_bytes(b"other"), ("acme", "payments"))
        assert not a.covers(None, ("acme", "payments"))


class TestExceptionsAreRecords:
    def test_an_exception_naming_a_hard_stop_is_a_request_problem(self) -> None:
        bad = Approval(
            "e1",
            "exception",
            "2027-01-01T00:00:00Z",
            digests=(DIGEST,),
            reason_codes=("R100", "R400"),
        )
        fine = Approval(
            "e2", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,), reason_codes=("R400",)
        )
        assert bad.names_a_hard_stop() and not fine.names_a_hard_stop()
        assert len(EvidenceSet(approvals=(bad, fine)).request_problems()) == 1
        assert EvidenceSet(approvals=(fine,)).request_problems() == []


class TestEvidence:
    def test_the_digest_does_not_depend_on_the_order_evidence_was_assembled_in(self) -> None:
        a, b = finding("A.1", line=1), finding("B.1", path="b.js", line=9)
        first = EvidenceSet(findings=(a, b), required_missing=("sbom", "provenance"))
        second = EvidenceSet(findings=(b, a), required_missing=("provenance", "sbom"))
        assert first.sha256() == second.sha256()
        assert first.sha256() != EvidenceSet(findings=(a,)).sha256()

    def test_the_analysis_key_ignores_what_a_tenant_adds_and_the_decision_key_does_not(
        self,
    ) -> None:
        one = EvidenceSet(
            findings=(finding("A.1", line=1),),
            intel=(IntelMatch("advisory", "GHSA-1", "osv", "2026-11-01T00:00:00Z"),),
            provenance=Provenance(2, "signer", True),
        )
        other = replace(
            one,
            approvals=(Approval("a1", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,)),),
            kill_listed=True,
            revoked=True,
            required_missing=("sbom",),
        )
        assert one.analysis_sha256() == other.analysis_sha256()
        assert one.sha256() != other.sha256()

    def test_the_analysis_key_moves_with_each_fact_about_the_bytes(self) -> None:
        base = EvidenceSet(findings=(finding("A.1", line=1),))
        key = base.analysis_sha256()
        assert EvidenceSet(findings=(finding("A.1", line=2),)).analysis_sha256() != key
        assert EvidenceSet(findings=base.findings, complete=False).analysis_sha256() != key
        assert (
            EvidenceSet(
                findings=base.findings, gaps=(GapFact("SUSPECT.SOURCE.UNPARSED_RUNNING.001"),)
            ).analysis_sha256()
            != key
        )
        assert (
            EvidenceSet(
                findings=base.findings,
                intel=(IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z"),),
            ).analysis_sha256()
            != key
        )
        assert (
            EvidenceSet(findings=base.findings, provenance=Provenance(1)).analysis_sha256() != key
        )

    def test_the_analysis_key_does_not_depend_on_the_order_evidence_was_assembled_in(self) -> None:
        a, b = finding("A.1", line=1), finding("B.1", path="b.js", line=9)
        assert (
            EvidenceSet(findings=(a, b)).analysis_sha256()
            == EvidenceSet(findings=(b, a)).analysis_sha256()
        )

    def test_a_scan_json_predicate_round_trips(self) -> None:
        evidence = EvidenceSet(
            findings=(finding(),),
            provenance=Provenance(2, "signer", True),
            intel=(IntelMatch("advisory", "GHSA-1", "osv", "2026-11-01T00:00:00Z"),),
            approvals=(
                Approval("a1", "exception", "2027-01-01T00:00:00Z", rule_ids=("SUSPECT.X.001",)),
            ),
        )
        assert EvidenceSet.from_json(evidence.to_json()) == evidence

    def test_withdrawn_intelligence_is_not_known_malware(self) -> None:
        live = IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z")
        gone = IntelMatch("known_malware", "M-2", "osv", "2026-11-01T00:00:00Z", withdrawn=True)
        assert EvidenceSet(intel=(live, gone)).known_malware() == (live,)

    def test_the_age_of_a_release_is_in_whole_days(self) -> None:
        artifact = ArtifactRef("package", "pkg:npm/x", released_at="2026-11-14T09:00:00Z")
        assert artifact.age_days(CLOCK) == 2
        assert ArtifactRef("package", "pkg:npm/x").age_days(CLOCK) is None


class TestTheContextKey:
    """BP-5-4: `context_key` is the sha256 of the canonical (point, environment, scope path, relation), for caching."""

    @staticmethod
    def context(**changes: Any) -> Context:
        base: dict[str, Any] = {"point": "cli", "environment": "production", "scope_path": ("acme", "web"), "relation": "direct"}
        return Context(**{**base, **changes})

    def test_it_is_the_sha256_of_the_canonical_four(self) -> None:
        expected = ArtifactDigests.of_bytes(
            ArtifactDigests.canonical_json({"point": "cli", "environment": "production", "scope_path": ["acme", "web"], "relation": "direct"})
        )
        assert self.context().context_key() == expected
        assert self.context().context_key().startswith("sha256:") and len(self.context().context_key()) == 71

    @pytest.mark.parametrize(
        "change",
        [{"point": "ide"}, {"environment": "staging"}, {"scope_path": ("acme",)}, {"scope_path": ("web", "acme")}, {"relation": "transitive"}],
        ids=["point", "environment", "scope", "scope order", "relation"],
    )
    def test_each_of_the_four_moves_it(self, change: dict[str, Any]) -> None:
        assert self.context(**change).context_key() != self.context().context_key()

    @pytest.mark.parametrize("change", [{"actor": "agent"}, {"online": False}, {"bundle_age_s": 5}, {"intel_age_s": 9}])
    def test_nothing_else_of_the_context_moves_it(self, change: dict[str, Any]) -> None:
        assert self.context(**change).context_key() == self.context().context_key()

    def test_the_same_four_given_in_another_order_are_the_same_key(self) -> None:
        a = Context(point="cli", environment="production", scope_path=("a",), relation="direct")
        b = Context(relation="direct", scope_path=("a",), environment="production", point="cli")
        assert a.context_key() == b.context_key()

    def test_a_scope_path_does_not_run_into_its_neighbour(self) -> None:
        assert self.context(scope_path=("ab", "c")).context_key() != self.context(scope_path=("a", "bc")).context_key()
