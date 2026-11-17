"""The artifact, context and evidence types: closed vocabularies, strict fields, a canonical evidence digest."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.evidence import (
    Approval,
    ArtifactRef,
    Context,
    EvidenceSet,
    FindingFact,
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
