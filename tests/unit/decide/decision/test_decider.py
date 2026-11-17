"""`Decider.decide`: the seven steps of the decision function (spec 5.3), one scenario each, and determinism."""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.schema_check import SchemaChecker
from cordon_scanner.contracts.schemas import ContractSchemas
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.decider import Decider
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
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import DecisionError, PolicyError
from cordon_scanner.decide.decision.table import CompiledPolicy

DIGEST = ArtifactDigests.of_bytes(b"the artifact")
CLOCK = datetime(2026, 11, 17, 8, 0, 30, tzinfo=UTC)

RULES = [
    {
        "id": "deny-malicious",
        "tier": "deny",
        "then": "block",
        "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
    },
    {
        "id": "deny-high",
        "tier": "deny",
        "then": "review",
        "when": {"finding.severity": ">=high", "finding.confidence": ">=medium"},
    },
    {
        "id": "young-release",
        "tier": "require",
        "then": "review",
        "when": {"version.age_days": "<3d"},
    },
    {
        "id": "provenance-critical",
        "tier": "require",
        "then": "block",
        "applies_to": {"subject.tags": "critical"},
        "require": {"provenance.slsa_level": ">=2"},
    },
    {
        "id": "allow-internal",
        "tier": "allow",
        "then": "allow",
        "when": {"subject.namespace": "@acme"},
        "obligations": ["O002"],
    },
]


class Fixtures:
    @staticmethod
    def policy(rules=None, defaults=None, **kw) -> CompiledPolicy:
        data = {
            "policy_schema": 2,
            "id": "acme/production",
            "version": 14,
            "scope": ["acme"],
            "rules": copy.deepcopy(RULES if rules is None else rules),
            "defaults": defaults or {"warn_until_measured": ["pypi"]},
        }
        data.update(kw)
        return PolicyCompiler.compile(PolicySource.from_json(data))

    @staticmethod
    def artifact(**kw) -> ArtifactRef:
        base = {
            "kind": "package",
            "subject_id": "pkg:npm/left-pad",
            "digest": DIGEST,
            "ecosystem": "npm",
            "released_at": "2026-06-01T00:00:00Z",
        }
        base.update(kw)
        return ArtifactRef(**base)

    @staticmethod
    def context(**kw) -> Context:
        base = {"point": "ci_gate", "environment": "production", "scope_path": ("acme", "payments")}
        base.update(kw)
        return Context(**base)

    @staticmethod
    def finding(
        category="suspicious",
        severity="medium",
        confidence="medium",
        rule="SUSPECT.X.001",
        path="a.js",
        line=1,
    ) -> FindingFact:
        return FindingFact(
            rule, severity, confidence, category, domain="supply_chain", path=path, line=line
        )

    @staticmethod
    def with_(evidence: EvidenceSet, **changes) -> EvidenceSet:
        return replace(evidence, **changes)

    @classmethod
    def decide(cls, evidence=None, policy=None, artifact=None, context=None, clock=CLOCK):
        return Decider.decide(
            artifact or cls.artifact(),
            context or cls.context(),
            policy or cls.policy(),
            evidence or EvidenceSet(),
            clock,
        )


F = Fixtures


class TestTheDefaults:
    def test_nothing_found_is_allowed_with_the_no_findings_reason(self) -> None:
        decision = F.decide()
        assert decision.state == "ALLOW" and decision.reason_codes == ("R903",)

    def test_the_decision_is_a_valid_decision_v1_predicate_naming_its_policy(self) -> None:
        decision = F.decide()
        assert SchemaChecker.errors(ContractSchemas.load("decision-v1"), decision.to_json()) == []
        assert decision.policy.id == "acme/production" and decision.policy.version == 14
        assert decision.policy.sha256 == F.policy().sha256

    @pytest.mark.parametrize(
        ("default", "state", "code"),
        [
            ("review", "REVIEW", "R700"),
            ("block", "BLOCK", "R700"),
            ("allow_with_conditions", "ALLOW_WITH_CONDITIONS", "R703"),
        ],
    )
    def test_a_stricter_default_applies_when_no_rule_does(self, default, state, code) -> None:
        decision = F.decide(policy=F.policy(defaults={"default": default}))
        assert decision.state == state and decision.reason_codes == (code,)


class TestHardStops:
    LIFTS = (
        Approval("a1", "approve", "2027-01-01T00:00:00Z", digests=(DIGEST,), scope_path=("acme",)),
        Approval("e1", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,)),
    )

    @pytest.mark.parametrize(
        ("evidence", "code"),
        [
            (
                EvidenceSet(
                    intel=(IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z"),)
                ),
                "R100",
            ),
            (EvidenceSet(revoked=True), "R101"),
            (EvidenceSet(integrity_ok=False), "R102"),
            (EvidenceSet(kill_listed=True), "R103"),
        ],
    )
    def test_each_blocks_and_no_approval_or_exception_lifts_it(self, evidence, code) -> None:
        decision = F.decide(F.with_(evidence, approvals=self.LIFTS))
        assert decision.state == "BLOCK" and decision.reason_codes == (code,)

    def test_withdrawn_intelligence_is_not_a_stop(self) -> None:
        gone = IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z", withdrawn=True)
        assert F.decide(EvidenceSet(intel=(gone,))).state == "ALLOW"


class TestCompleteness:
    @pytest.mark.parametrize(
        ("evidence", "context", "code"),
        [
            (EvidenceSet(complete=False), {}, "R204"),
            (EvidenceSet(unresolved=True), {}, "R203"),
            (EvidenceSet(required_missing=("sbom",)), {}, "R200"),
            (EvidenceSet(gaps=(GapFact("OPERATIONAL.SOURCE.UNPARSED", "a.js"),)), {}, "R204"),
            (EvidenceSet(), {"intel_age_s": 8 * 86400}, "R201"),
            (EvidenceSet(), {"bundle_age_s": 100 * 3600}, "R202"),
            (EvidenceSet(provenance=Provenance(3, "s", verified=False)), {}, "R205"),
        ],
    )
    def test_a_shortfall_blocks_by_default_and_says_why(self, evidence, context, code) -> None:
        policy = F.policy(defaults={"max_intel_age": "7d", "bundle_max_age": "72h"})
        decision = F.decide(evidence, policy=policy, context=F.context(**context))
        assert decision.state == "BLOCK" and code in decision.reason_codes

    def test_each_is_at_the_level_the_policy_sets_for_the_environment(self) -> None:
        policy = F.policy(defaults={"on_incomplete": {"*": "block", "dev": "review", "ci": "warn"}})
        incomplete = EvidenceSet(complete=False)
        assert (
            F.decide(incomplete, policy=policy, context=F.context(environment="production")).state
            == "BLOCK"
        )
        assert (
            F.decide(incomplete, policy=policy, context=F.context(environment="dev")).state
            == "REVIEW"
        )
        warned = F.decide(incomplete, policy=policy, context=F.context(environment="ci"))
        assert warned.state == "ALLOW" and warned.reason_codes == ("R204", "R903")

    def test_an_expired_policy_bundle_is_a_shortfall(self) -> None:
        policy = F.policy(expires_at="2026-11-17T08:00:00Z")
        assert "R202" in F.decide(policy=policy).reason_codes
        assert "R202" not in F.decide(policy=policy, clock=CLOCK - timedelta(hours=1)).reason_codes

    def test_unverifiable_provenance_matters_only_when_a_rule_reads_provenance(self) -> None:
        evidence = EvidenceSet(provenance=Provenance(3, "s", verified=False))
        quiet = F.policy(rules=[RULES[0]])
        assert "R205" not in F.decide(evidence, policy=quiet).reason_codes

    def test_content_gaps_can_be_set_to_warn(self) -> None:
        policy = F.policy(defaults={"on_gaps": "warn"})
        decision = F.decide(
            EvidenceSet(gaps=(GapFact("OPERATIONAL.SOURCE.UNPARSED", "a.js"),)), policy=policy
        )
        assert decision.state == "ALLOW" and "R204" in decision.reason_codes


class TestRules:
    def test_a_deny_rule_blocks_and_gives_a_reason_for_each_finding_it_matched(self) -> None:
        evidence = EvidenceSet(
            findings=(
                F.finding("malicious", "high", "high", "MALWARE.A.001", "b.js", 7),
                F.finding("malicious", "high", "medium", "MALWARE.B.001", "a.js", 2),
                F.finding("suspicious", "low", "low"),
            )
        )
        decision = F.decide(evidence)
        assert decision.state == "BLOCK" and decision.reason_codes == ("R400",)
        shown = [
            (r.rule_id, r.path, r.line)
            for r in decision.explanation.reasons
            if "deny-malicious" in r.text
        ]
        assert shown == [("MALWARE.A.001", "b.js", 7), ("MALWARE.B.001", "a.js", 2)]

    def test_a_suspicious_finding_that_fails_the_rule_is_r401_and_a_vulnerable_one_r404(
        self,
    ) -> None:
        sus = F.decide(EvidenceSet(findings=(F.finding("suspicious", "high", "high"),)))
        assert sus.state == "REVIEW" and sus.reason_codes == ("R401",)
        vuln = F.decide(EvidenceSet(findings=(F.finding("vulnerable", "critical", "high"),)))
        assert vuln.reason_codes == ("R404",)

    def test_a_finding_below_the_floor_is_not_a_reason(self) -> None:
        assert (
            F.decide(EvidenceSet(findings=(F.finding("malicious", "high", "low"),))).state
            == "ALLOW"
        )

    def test_a_require_rule_that_fires_sends_the_artifact_to_review_with_its_reason(self) -> None:
        young = F.decide(artifact=F.artifact(released_at="2026-11-16T00:00:00Z"))
        assert young.state == "REVIEW" and young.reason_codes == ("R503",)

    def test_a_requirement_that_is_unmet_blocks_and_one_that_is_met_does_not(self) -> None:
        critical = F.artifact(tags=("critical",))
        assert F.decide(artifact=critical).reason_codes == ("R500",)
        assert F.decide(artifact=critical).state == "BLOCK"
        met = EvidenceSet(provenance=Provenance(3, "s"))
        assert F.decide(met, artifact=critical).state == "ALLOW"

    def test_an_allow_rule_allows_with_its_obligations_and_never_over_a_deny(self) -> None:
        internal = F.artifact(namespace="@acme")
        allowed = F.decide(artifact=internal)
        assert (
            allowed.state == "ALLOW"
            and allowed.obligations == ("O002",)
            and allowed.reason_codes == ("R900",)
        )
        denied = F.decide(
            EvidenceSet(findings=(F.finding("malicious", "high", "high"),)), artifact=internal
        )
        assert denied.state == "BLOCK" and denied.obligations == ()

    def test_the_strictest_outcome_among_the_rules_that_fired_wins(self) -> None:
        both = F.decide(
            EvidenceSet(findings=(F.finding("suspicious", "high", "high"),)),
            artifact=F.artifact(tags=("critical",)),
        )
        assert both.state == "BLOCK" and set(both.reason_codes) == {"R401", "R500"}


class TestApprovalsAndExceptions:
    BLOCKED = EvidenceSet(findings=(F.finding("malicious", "high", "high"),))

    def approval(self, kind="approve", **kw) -> Approval:
        return Approval(
            "a1",
            kind,
            kw.pop("expires_at", "2027-01-01T00:00:00Z"),
            digests=kw.pop("digests", (DIGEST,)),
            scope_path=kw.pop("scope_path", ("acme",)),
            **kw,
        )

    def test_an_approval_for_this_digest_lifts_a_rule_block_and_pins_the_digest(self) -> None:
        decision = F.decide(F.with_(self.BLOCKED, approvals=(self.approval(),)))
        assert (
            decision.state == "ALLOW"
            and decision.reason_codes == ("R901",)
            and decision.obligations == ("O001",)
        )
        assert "deny-malicious" in decision.explanation.reasons[0].text

    def test_an_approval_with_conditions_gives_allow_with_conditions(self) -> None:
        decision = F.decide(
            F.with_(
                self.BLOCKED,
                approvals=(self.approval("approve_with_conditions", conditions=("pin",)),),
            )
        )
        assert decision.state == "ALLOW_WITH_CONDITIONS" and decision.reason_codes == (
            "R703",
            "R901",
        )

    @pytest.mark.parametrize(
        "approval",
        [
            Approval(
                "a1",
                "approve",
                "2027-01-01T00:00:00Z",
                digests=(ArtifactDigests.of_bytes(b"other"),),
                scope_path=("acme",),
            ),
            Approval(
                "a1", "approve", "2026-11-17T08:00:00Z", digests=(DIGEST,), scope_path=("acme",)
            ),
            Approval(
                "a1",
                "approve",
                "2027-01-01T00:00:00Z",
                digests=(DIGEST,),
                scope_path=("acme",),
                revoked=True,
            ),
            Approval(
                "a1", "approve", "2027-01-01T00:00:00Z", digests=(DIGEST,), scope_path=("other",)
            ),
        ],
    )
    def test_an_approval_for_another_digest_an_expired_or_revoked_one_or_another_scope_does_nothing(
        self, approval
    ) -> None:
        assert F.decide(F.with_(self.BLOCKED, approvals=(approval,))).state == "BLOCK"

    def test_an_approval_does_not_lift_a_completeness_block(self) -> None:
        evidence = F.with_(self.BLOCKED, approvals=(self.approval(),), complete=False)
        assert F.decide(evidence).state == "BLOCK"

    def exception(self, **kw) -> Approval:
        return Approval(
            "e1",
            "exception",
            kw.pop("expires_at", "2027-01-01T00:00:00Z"),
            digests=kw.pop("digests", (DIGEST,)),
            **kw,
        )

    def test_an_exception_that_names_no_outcome_allows_with_excepted_r702(self) -> None:
        decision = F.decide(F.with_(self.BLOCKED, approvals=(self.exception(),)))
        assert decision.state == "ALLOW" and decision.reason_codes == ("R702",)
        assert "deny-malicious" in decision.explanation.reasons[0].text

    def test_an_exception_for_one_rule_leaves_the_other_rules_standing(self) -> None:
        only_one = self.exception(rule_ids=("deny-malicious",))
        decision = F.decide(F.with_(self.BLOCKED, approvals=(only_one,)))
        assert decision.state == "REVIEW" and set(decision.reason_codes) == {"R400", "R702"}

    def test_an_exception_that_names_review_gives_review_and_keeps_the_reasons(self) -> None:
        decision = F.decide(F.with_(self.BLOCKED, approvals=(self.exception(outcome="REVIEW"),)))
        assert decision.state == "REVIEW" and set(decision.reason_codes) == {"R400", "R702"}

    def test_an_exception_with_conditions_allows_with_conditions(self) -> None:
        decision = F.decide(F.with_(self.BLOCKED, approvals=(self.exception(conditions=("log",)),)))
        assert decision.state == "ALLOW_WITH_CONDITIONS"

    @pytest.mark.parametrize(
        "exception",
        [
            Approval("e1", "exception", "2026-11-17T08:00:00Z", digests=(DIGEST,)),
            Approval("e1", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,), revoked=True),
            Approval(
                "e1", "exception", "2027-01-01T00:00:00Z", digests=(ArtifactDigests.of_bytes(b"x"),)
            ),
            Approval(
                "e1",
                "exception",
                "2027-01-01T00:00:00Z",
                digests=(DIGEST,),
                rule_ids=("young-release",),
            ),
            Approval(
                "e1", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,), reason_codes=("R401",)
            ),
            Approval(
                "e1", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,), scope_path=("other",)
            ),
        ],
    )
    def test_an_expired_revoked_or_unrelated_exception_does_nothing(self, exception) -> None:
        assert F.decide(F.with_(self.BLOCKED, approvals=(exception,))).state == "BLOCK"

    def test_an_exception_can_be_limited_to_a_reason_code(self) -> None:
        assert (
            F.decide(
                F.with_(self.BLOCKED, approvals=(self.exception(reason_codes=("R400",)),))
            ).state
            == "ALLOW"
        )

    def test_the_policy_caps_what_an_exception_may_do(self) -> None:
        asking_allow = F.with_(self.BLOCKED, approvals=(self.exception(),))
        assert (
            F.decide(asking_allow, policy=F.policy(defaults={"exceptions": "review"})).state
            == "REVIEW"
        )
        assert (
            F.decide(asking_allow, policy=F.policy(defaults={"exceptions": "none"})).state
            == "BLOCK"
        )
        asking_review = F.with_(self.BLOCKED, approvals=(self.exception(outcome="REVIEW"),))
        assert (
            F.decide(asking_review, policy=F.policy(defaults={"exceptions": "review"})).state
            == "REVIEW"
        )

    def test_an_exception_over_a_review_allows(self) -> None:
        exception = self.exception(rule_ids=("young-release",))
        young = F.artifact(released_at="2026-11-16T00:00:00Z")
        decision = F.decide(EvidenceSet(approvals=(exception,)), artifact=young)
        assert decision.state == "ALLOW" and decision.reason_codes == ("R702",)

    def test_an_exception_that_names_a_hard_stop_is_rejected_in_the_request_and_ignored_in_the_call(
        self,
    ) -> None:
        malware = EvidenceSet(
            intel=(IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z"),),
            approvals=(self.exception(reason_codes=("R100",)),),
        )
        assert F.decide(malware).state == "BLOCK" and F.decide(malware).reason_codes == ("R100",)
        request = {
            "artifact": F.artifact().to_json(),
            "context": F.context().to_json(),
            "policy": F.policy().to_json(),
            "evidence": malware.to_json(),
            "clock": "2026-11-17T08:00:30Z",
        }
        with pytest.raises(DecisionError, match="hard stop"):
            Decider.decide_json(request)


class TestTheMeasuredQualityGuard:
    PYPI: ClassVar[dict[str, str]] = {"ecosystem": "pypi"}
    MALICIOUS = EvidenceSet(findings=(F.finding("malicious", "high", "high"),))

    def test_a_content_block_in_an_unmeasured_ecosystem_is_a_review(self) -> None:
        decision = F.decide(self.MALICIOUS, artifact=F.artifact(**self.PYPI))
        assert decision.state == "REVIEW" and set(decision.reason_codes) == {"R300", "R400"}

    def test_the_same_finding_blocks_where_the_ecosystem_is_measured(self) -> None:
        assert F.decide(self.MALICIOUS, artifact=F.artifact(ecosystem="npm")).state == "BLOCK"

    def test_a_block_with_another_cause_stays_a_block(self) -> None:
        critical = F.artifact(tags=("critical",), **self.PYPI)
        assert F.decide(self.MALICIOUS, artifact=critical).state == "BLOCK"
        assert (
            F.decide(self.MALICIOUS, artifact=F.artifact(**self.PYPI), context=F.context()).state
            == "REVIEW"
        )
        assert (
            F.decide(
                F.with_(self.MALICIOUS, complete=False), artifact=F.artifact(**self.PYPI)
            ).state
            == "BLOCK"
        )

    def test_kinds_have_their_short_names(self) -> None:
        policy = F.policy(defaults={"warn_until_measured": ["mcp"]})
        server = F.artifact(kind="mcp_server", subject_id="mcp:npm/x", ecosystem=None)
        assert F.decide(self.MALICIOUS, policy=policy, artifact=server).state == "REVIEW"


class TestDeterminism:
    EVIDENCE = EvidenceSet(
        findings=(
            F.finding("malicious", "high", "high", "A.1", "x.js", 3),
            F.finding("suspicious", "high", "high", "B.1", "a.js", 1),
            F.finding("suspicious", "low", "low", "C.1"),
        )
    )

    def test_the_same_call_gives_the_same_bytes(self) -> None:
        assert (
            F.decide(self.EVIDENCE).canonical_bytes() == F.decide(self.EVIDENCE).canonical_bytes()
        )

    def test_the_order_the_evidence_was_assembled_in_does_not_matter(self) -> None:
        reversed_ = F.with_(self.EVIDENCE, findings=tuple(reversed(self.EVIDENCE.findings)))
        assert F.decide(reversed_).canonical_bytes() == F.decide(self.EVIDENCE).canonical_bytes()

    def test_the_digest_is_stable_within_a_clock_bucket_and_moves_with_it(self) -> None:
        base = F.decide(self.EVIDENCE).inputs_digest
        assert F.decide(self.EVIDENCE, clock=CLOCK + timedelta(seconds=20)).inputs_digest == base
        later = F.decide(self.EVIDENCE, clock=CLOCK + timedelta(seconds=40))
        assert later.inputs_digest != base and later.clock_bucket == "2026-11-17T08:01:00Z"

    def test_the_digest_moves_with_each_input(self) -> None:
        base = F.decide(self.EVIDENCE).inputs_digest
        assert F.decide(self.EVIDENCE, artifact=F.artifact(version="2.0.0")).inputs_digest != base
        assert (
            F.decide(self.EVIDENCE, context=F.context(environment="staging")).inputs_digest != base
        )
        assert F.decide(EvidenceSet(findings=self.EVIDENCE.findings[:1])).inputs_digest != base
        assert F.decide(self.EVIDENCE, policy=F.policy(version=15)).inputs_digest != base

    def test_a_clock_without_a_zone_and_an_altered_policy_are_refused(self) -> None:
        with pytest.raises(DecisionError, match="zone"):
            F.decide(clock=datetime(2026, 11, 17, 8, 0))
        shape = F.policy().to_json()
        shape["rules"][0]["then"] = "allow"
        with pytest.raises(PolicyError, match="digest"):
            F.decide(policy=CompiledPolicy.from_json(shape))

    def test_the_json_call_is_the_same_decision(self) -> None:
        request = {
            "artifact": F.artifact().to_json(),
            "context": F.context().to_json(),
            "policy": F.policy().to_json(),
            "evidence": self.EVIDENCE.to_json(),
            "clock": "2026-11-17T08:00:30Z",
        }
        assert Decider.decide_json(request) == F.decide(self.EVIDENCE).to_json()
        with pytest.raises(DecisionError):
            Decider.decide_json({**request, "extra": 1})
        with pytest.raises(DecisionError):
            Decider.decide_json({key: value for key, value in request.items() if key != "clock"})
