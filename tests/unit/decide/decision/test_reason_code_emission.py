"""Row BP-5-17: every reason code has a rule or stage that can emit it and a test that emits it.

The registry (`contracts/reason_codes.py`) lists 36 codes. Each is in exactly one of two tables here:

* `STAGE`: a stage of `decide()` emits it from facts alone (a hard stop, a shortfall of evidence, a finding of a category, an approval,
  a default). The fixture builds the inputs and the test checks the code is in the decision.
* `RULE_ONLY`: no stage emits it by itself, and it appears in a decision only when a policy rule names it (`reason`). The fixture is
  that rule, and the table says what is missing for a stage to emit it on its own.

A new code in the registry fails `test_every_code_is_in_one_table` until it is given a fixture, so a code nobody can produce cannot
be added unnoticed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import (
    Approval,
    ArtifactRef,
    EvidenceSet,
    FindingFact,
    IntelMatch,
    Provenance,
)
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import PolicyError
from cordon_scanner.decide.points import PointRuntime

CLOCK = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
DIGEST = ArtifactDigests.of_bytes(b"left-pad 1.3.0")
ARTIFACT = ArtifactRef(
    kind="package",
    subject_id="pkg:npm/left-pad",
    digest=DIGEST,
    ecosystem="npm",
    released_at="2026-06-01T00:00:00Z",
)
FRESH = ArtifactRef(
    kind="package",
    subject_id="pkg:npm/left-pad",
    digest=DIGEST,
    ecosystem="npm",
    released_at="2026-11-18T10:00:00Z",
)


class Make:
    """The pieces a fixture is made of."""

    @staticmethod
    def policy(
        rules: list[dict[str, Any]] | None = None,
        defaults: dict[str, Any] | None = None,
        expires_at: str | None = None,
    ):
        source: dict[str, Any] = {
            "policy_schema": 2,
            "id": "acme/policy",
            "version": 1,
            "scope": ["acme"],
            "rules": rules or [],
            "defaults": defaults or {},
        }
        if expires_at is not None:
            source["expires_at"] = expires_at
        return PolicyCompiler.compile(PolicySource.from_json(source))

    @staticmethod
    def ask(
        policy,
        evidence: EvidenceSet | None = None,
        artifact: ArtifactRef = ARTIFACT,
        **context: Any,
    ) -> Decision:
        return PointRuntime.ask(
            "ci_gate",
            artifact,
            evidence or EvidenceSet(),
            policy,
            CLOCK,
            environment="production",
            scope_path=("acme",),
            **context,
        )

    @staticmethod
    def finding(category: str, severity: str = "high") -> FindingFact:
        return FindingFact(
            rule_id=f"TEST.{category.upper()}.001",
            severity=severity,
            confidence="high",
            category=category,
            domain="supply_chain",
            path="index.js",
            line=3,
        )

    @staticmethod
    def deny_on(category: str) -> dict[str, Any]:
        return {
            "id": f"deny-{category}",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": category},
        }

    @staticmethod
    def approval(kind: str, **more: Any) -> Approval:
        return Approval(
            id="APR-1",
            kind=kind,
            expires_at="2026-12-31T00:00:00Z",
            digests=(DIGEST,),
            scope_path=("acme",),
            **more,
        )


class Stage:
    """One method per code a stage emits: it builds the inputs and returns the decision."""

    @staticmethod
    def R100() -> Decision:
        match = IntelMatch(
            kind="known_malware", id="MAL-1", source="osv", first_seen="2026-11-01T00:00:00Z"
        )
        return Make.ask(Make.policy(), EvidenceSet(intel=(match,)))

    @staticmethod
    def R101() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(revoked=True))

    @staticmethod
    def R102() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(integrity_ok=False))

    @staticmethod
    def R103() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(kill_listed=True))

    @staticmethod
    def R200() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(required_missing=("sbom",)))

    @staticmethod
    def R201() -> Decision:
        return Make.ask(Make.policy(defaults={"max_intel_age": "1d"}), intel_age_s=3 * 86400)

    @staticmethod
    def R202() -> Decision:
        return Make.ask(Make.policy(expires_at="2026-11-19T09:00:00Z"))

    @staticmethod
    def R203() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(unresolved=True))

    @staticmethod
    def R204() -> Decision:
        return Make.ask(Make.policy(), EvidenceSet(complete=False))

    @staticmethod
    def R205() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "slsa",
                    "tier": "require",
                    "then": "review",
                    "when": {"provenance.slsa_level": "<3"},
                }
            ]
        )
        return Make.ask(policy, EvidenceSet(provenance=Provenance(slsa_level=3, verified=False)))

    @staticmethod
    def R300() -> Decision:
        policy = Make.policy([Make.deny_on("malicious")], {"warn_until_measured": ["npm"]})
        return Make.ask(policy, EvidenceSet(findings=(Make.finding("malicious"),)))

    @staticmethod
    def R400() -> Decision:
        return Make.ask(
            Make.policy([Make.deny_on("malicious")]),
            EvidenceSet(findings=(Make.finding("malicious"),)),
        )

    @staticmethod
    def R401() -> Decision:
        return Make.ask(
            Make.policy([Make.deny_on("suspicious")]),
            EvidenceSet(findings=(Make.finding("suspicious"),)),
        )

    @staticmethod
    def R404() -> Decision:
        return Make.ask(
            Make.policy([Make.deny_on("vulnerable")]),
            EvidenceSet(findings=(Make.finding("vulnerable"),)),
        )

    @staticmethod
    def R500() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "slsa",
                    "tier": "require",
                    "then": "review",
                    "when": {"provenance.slsa_level": "<3"},
                }
            ]
        )
        return Make.ask(policy, EvidenceSet(provenance=Provenance(slsa_level=1)))

    @staticmethod
    def R501() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "signer",
                    "tier": "require",
                    "then": "review",
                    "require": {"signature.signer": "release@acme.example"},
                }
            ]
        )
        return Make.ask(
            policy, EvidenceSet(provenance=Provenance(slsa_level=3, signer="someone@else.example"))
        )

    @staticmethod
    def R503() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "young",
                    "tier": "require",
                    "then": "review",
                    "when": {"version.age_days": "<3d"},
                }
            ]
        )
        return Make.ask(policy, artifact=FRESH)

    @staticmethod
    def R700() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "needs-approval",
                    "tier": "require",
                    "then": "review",
                    "require": {"approval": "present"},
                }
            ]
        )
        return Make.ask(policy)

    @staticmethod
    def R702() -> Decision:
        policy = Make.policy([Make.deny_on("suspicious")])
        evidence = EvidenceSet(
            findings=(Make.finding("suspicious"),),
            approvals=(Make.approval("exception", rule_ids=("deny-suspicious",)),),
        )
        return Make.ask(policy, evidence)

    @staticmethod
    def R703() -> Decision:
        policy = Make.policy([Make.deny_on("suspicious")])
        evidence = EvidenceSet(
            findings=(Make.finding("suspicious"),),
            approvals=(Make.approval("approve_with_conditions", conditions=("pin the version",)),),
        )
        return Make.ask(policy, evidence)

    @staticmethod
    def R900() -> Decision:
        policy = Make.policy(
            [
                {
                    "id": "trusted",
                    "tier": "allow",
                    "then": "allow",
                    "when": {"subject.namespace": "@acme"},
                }
            ]
        )
        return Make.ask(
            policy, artifact=ArtifactRef.from_json({**ARTIFACT.to_json(), "namespace": "@acme"})
        )

    @staticmethod
    def R901() -> Decision:
        policy = Make.policy([Make.deny_on("suspicious")])
        evidence = EvidenceSet(
            findings=(Make.finding("suspicious"),), approvals=(Make.approval("approve"),)
        )
        return Make.ask(policy, evidence)

    @staticmethod
    def R903() -> Decision:
        return Make.ask(Make.policy())


class Codes:
    STAGE: ClassVar[tuple[str, ...]] = (
        "R100", "R101", "R102", "R103",
        "R200", "R201", "R202", "R203", "R204", "R205",
        "R300",
        "R400", "R401", "R404",
        "R500", "R501", "R503",
        "R700", "R702", "R703",
        "R900", "R901", "R903",
    )  # fmt: skip
    #: code -> what is missing for a stage to emit it without a rule naming it, and the row that supplies it.
    RULE_ONLY: ClassVar[dict[str, str]] = {
        "R402": "BP-5-18: the scanner's secret findings arrive as category `policy` or `suspicious`; no category says `secret`, so a rule names R402.",
        "R403": "BP-5-18: intelligence carries `known_malware` and `advisory` only; `exploited` is not a kind yet, so a rule names R403.",
        "R405": "BP-5-18: no licence fact is in the evidence; a rule on a licence finding names R405.",
        "R502": "BP-5-19: no publisher-age fact is in the evidence (no producer of it in the control plane).",
        "R504": "BP-5-19: the name-risk finding arrives as a suspicious finding; no lookalike fact is in the evidence.",
        "R505": "BP-5-19: no registry host is in the artifact reference, so no predicate can compare it with an allow list.",
        "R600": "BP-5-20: MCP tool-description findings arrive as category `suspicious` (R401); no domain-to-code mapping yet.",
        "R601": "BP-5-20: skill instruction findings arrive as category `suspicious` (R401); no domain-to-code mapping yet.",
        "R602": "BP-5-20: excessive capability is a finding of category `policy`; no domain-to-code mapping yet.",
        "R603": "BP-5-20: model and provider approval is a policy list on `subject.id`; the rule names R603.",
        "R604": "BP-5-20: the tool-list digest of a session start (T0) against the one before (T1) is not in the evidence yet.",
        "R701": "BP-5-21: an expired approval is dropped from the call (`Approval.active`) and nothing records that it was; M9 filters before the call.",
        "R902": "BP-5-21: a tenant allow list is a policy list; the allow rule over it names R902.",
    }  # fmt: skip

    @classmethod
    def registry(cls) -> list[str]:
        return [entry.code for entry in ReasonCodes.ALL]


class TestEveryCodeIsProducedByATest:
    def test_every_code_is_in_one_table(self) -> None:
        both = set(Codes.STAGE) & set(Codes.RULE_ONLY)
        assert not both, f"in both tables: {sorted(both)}"
        missing = set(Codes.registry()) - set(Codes.STAGE) - set(Codes.RULE_ONLY)
        assert not missing, f"no fixture for: {sorted(missing)}"
        unknown = (set(Codes.STAGE) | set(Codes.RULE_ONLY)) - set(Codes.registry())
        assert not unknown, f"a fixture for a code that is not registered: {sorted(unknown)}"

    @pytest.mark.parametrize("code", Codes.STAGE)
    def test_a_stage_emits_it_from_the_facts_alone(self, code: str) -> None:
        decision = getattr(Stage, code)()
        assert code in decision.reason_codes, (code, decision.reason_codes)

    @pytest.mark.parametrize("code", sorted(Codes.RULE_ONLY))
    def test_a_rule_that_names_it_makes_the_library_emit_it(self, code: str) -> None:
        policy = Make.policy(
            [
                {
                    "id": "names-the-code",
                    "tier": "require",
                    "then": "review",
                    "when": {"subject.ecosystem": "npm"},
                    "reason": code,
                }
            ]
        )
        decision = Make.ask(policy)
        assert code in decision.reason_codes and decision.state == "REVIEW"

    @pytest.mark.parametrize("code", sorted(Codes.RULE_ONLY))
    def test_what_is_missing_is_written_down_against_a_row(self, code: str) -> None:
        text = Codes.RULE_ONLY[code]
        assert text.startswith("BP-5-") and len(text) > 40

    def test_a_rule_cannot_name_a_code_the_registry_does_not_have(self) -> None:
        with pytest.raises(PolicyError):
            Make.policy(
                [
                    {
                        "id": "x",
                        "tier": "require",
                        "then": "review",
                        "when": {"subject.ecosystem": "npm"},
                        "reason": "R999",
                    }
                ]
            )

    def test_the_decisions_of_the_fixtures_are_the_same_on_a_second_run(self) -> None:
        for code in Codes.STAGE:
            first, second = getattr(Stage, code)(), getattr(Stage, code)()
            assert first.canonical_bytes() == second.canonical_bytes(), code
