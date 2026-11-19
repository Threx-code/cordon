"""Typed predicates: a closed field table, no expressions, errors that name the path."""

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
from cordon_scanner.decide.decision.facts import Facts, Matcher
from cordon_scanner.decide.decision.predicates import Condition, PredicateCompiler
from cordon_scanner.decide.decision.records import PolicyError

DIGEST = ArtifactDigests.of_bytes(b"artifact")
CLOCK = datetime(2026, 11, 17, 8, 0, tzinfo=UTC)
LISTS = {"internal": ("@acme", "acme-*"), "signers": ("https://ci.example/release",)}


class Build:
    @staticmethod
    def compile(predicate: dict) -> tuple[Condition, ...]:
        return PredicateCompiler.compile(predicate, LISTS, "rules.r.when")

    @staticmethod
    def facts(**kw) -> Facts:
        artifact = ArtifactRef(
            "package",
            "pkg:npm/%40acme/billing",
            digest=DIGEST,
            ecosystem="npm",
            namespace=kw.pop("namespace", "@acme"),
            tags=kw.pop("tags", ("critical",)),
            released_at=kw.pop("released_at", "2026-11-16T08:00:00Z"),
        )
        context = Context("ci_gate", kw.pop("environment", "production"), ("acme", "payments"))
        evidence = EvidenceSet(
            findings=kw.pop("findings", ()),
            provenance=kw.pop("provenance", None),
            approvals=kw.pop("approvals", ()),
            intel=kw.pop("intel", ()),
        )
        return Facts.of(artifact, context, evidence, CLOCK)

    @staticmethod
    def finding(
        category="suspicious", severity="high", confidence="medium", rule="SUSPECT.X.001"
    ) -> FindingFact:
        return FindingFact(
            rule, severity, confidence, category, domain="supply_chain", path="a.js", line=1
        )


class TestCompiling:
    @pytest.mark.parametrize(
        ("predicate", "field", "op", "value"),
        [
            ({"finding.category": "malicious"}, "finding.category", "eq", "malicious"),
            ({"finding.confidence": ">=medium"}, "finding.confidence", "ge", "medium"),
            ({"finding.severity": "<high"}, "finding.severity", "lt", "high"),
            ({"version.age_days": "<3d"}, "version.age_days", "lt", 3),
            ({"version.age_days": {"ge": 7}}, "version.age_days", "ge", 7),
            ({"provenance.slsa_level": ">=2"}, "provenance.slsa_level", "ge", 2),
            (
                {"subject.namespace": {"in": "internal"}},
                "subject.namespace",
                "in",
                ("@acme", "acme-*"),
            ),
            ({"subject.id": {"glob": "pkg:npm/*"}}, "subject.id", "glob", "pkg:npm/*"),
            ({"intel.known_malware": True}, "intel.known_malware", "eq", True),
            ({"approval": "present"}, "approval", "eq", "present"),
            (
                {"context.environment": {"in": ["production", "staging"]}},
                "context.environment",
                "in",
                ("production", "staging"),
            ),
        ],
    )
    def test_each_form_compiles_to_one_condition(self, predicate, field, op, value) -> None:
        assert Build.compile(predicate) == (Condition(field, op, value),)

    def test_conditions_are_sorted_so_the_same_predicate_is_one_table(self) -> None:
        a = Build.compile({"version.age_days": "<3d", "approval": "absent"})
        b = Build.compile({"approval": "absent", "version.age_days": "<3d"})
        assert a == b and [item.field for item in a] == ["approval", "version.age_days"]

    @pytest.mark.parametrize(
        ("predicate", "needle"),
        [
            ({"finding.sevrity": "high"}, "unknown field"),
            ({"finding.category": "dubious"}, "not one of"),
            ({"finding.category": {"glob": "mal*"}}, "does not take 'glob'"),
            ({"intel.known_malware": "yes"}, "true or false"),
            ({"version.age_days": "<soon"}, "whole number"),
            ({"subject.namespace": {"in": "nowhere"}}, "no list named"),
            ({"subject.namespace": {"in": []}}, "non-empty list"),
            ({"subject.namespace": {"in": ["a"], "glob": "b"}}, "one operator"),
            ({"subject.namespace": {"matches": "a"}}, "unknown operator"),
            ({"subject.namespace": ""}, "non-empty string"),
        ],
    )
    def test_an_ill_formed_predicate_is_an_error_naming_the_path(self, predicate, needle) -> None:
        with pytest.raises(PolicyError, match=needle) as raised:
            Build.compile(predicate)
        assert "rules.r.when" in str(raised.value)

    def test_a_predicate_must_be_an_object(self) -> None:
        with pytest.raises(PolicyError):
            PredicateCompiler.compile(["finding.category"], {}, "rules.r.when")  # type: ignore[arg-type]
        assert PredicateCompiler.compile(None, {}, "rules.r.when") == ()


class TestEvaluating:
    def test_finding_conditions_must_hold_for_one_finding(self) -> None:
        both = Build.compile({"finding.category": "malicious", "finding.confidence": ">=medium"})
        split = Build.facts(
            findings=(
                Build.finding("malicious", confidence="low"),
                Build.finding("suspicious", confidence="high"),
            )
        )
        assert not Matcher.evaluate(both, split).matched
        one = Build.facts(
            findings=(Build.finding("malicious", confidence="high"), Build.finding("suspicious"))
        )
        match = Matcher.evaluate(both, one)
        assert match.matched and [item.category for item in match.findings] == ["malicious"]

    def test_ordered_fields_compare_by_their_scale(self) -> None:
        conditions = Build.compile({"finding.severity": ">=high"})
        assert Matcher.evaluate(
            conditions, Build.facts(findings=(Build.finding(severity="critical"),))
        ).matched
        assert not Matcher.evaluate(
            conditions, Build.facts(findings=(Build.finding(severity="medium"),))
        ).matched

    def test_a_fact_that_is_not_known_matches_nothing(self) -> None:
        assert not Matcher.evaluate(
            Build.compile({"version.age_days": "<3d"}), Build.facts(released_at=None)
        ).matched
        assert not Matcher.evaluate(
            Build.compile({"provenance.slsa_level": ">=0"}), Build.facts()
        ).matched

    def test_the_age_is_in_whole_days(self) -> None:
        young = Build.compile({"version.age_days": "<3d"})
        assert Matcher.evaluate(young, Build.facts(released_at="2026-11-16T08:00:00Z")).matched
        assert not Matcher.evaluate(young, Build.facts(released_at="2026-11-10T08:00:00Z")).matched

    def test_tags_namespaces_and_globs(self) -> None:
        assert Matcher.evaluate(Build.compile({"subject.tags": "critical"}), Build.facts()).matched
        assert not Matcher.evaluate(
            Build.compile({"subject.tags": "internal"}), Build.facts()
        ).matched
        assert Matcher.evaluate(
            Build.compile({"subject.namespace": {"in": "internal"}}), Build.facts()
        ).matched
        assert Matcher.evaluate(
            Build.compile({"subject.id": {"glob": "pkg:npm/*"}}), Build.facts()
        ).matched

    def test_unverified_provenance_counts_as_level_zero_and_names_no_signer(self) -> None:
        facts = Build.facts(provenance=Provenance(3, "https://ci.example/release", verified=False))
        assert not Matcher.evaluate(Build.compile({"provenance.slsa_level": ">=1"}), facts).matched
        assert not Matcher.evaluate(
            Build.compile({"signature.signer": {"in": "signers"}}), facts
        ).matched
        good = Build.facts(provenance=Provenance(3, "https://ci.example/release"))
        assert Matcher.evaluate(
            Build.compile({"signature.signer": {"in": "signers"}, "provenance.slsa_level": ">=2"}),
            good,
        ).matched

    def test_an_approval_is_present_only_when_active_and_it_lists_this_digest(self) -> None:
        live = Approval(
            "a1", "approve", "2027-01-01T00:00:00Z", digests=(DIGEST,), scope_path=("acme",)
        )
        other = Approval(
            "a2", "approve", "2027-01-01T00:00:00Z", digests=(ArtifactDigests.of_bytes(b"x"),)
        )
        expired = Approval("a3", "approve", "2026-11-17T08:00:00Z", digests=(DIGEST,))
        exception = Approval("a4", "exception", "2027-01-01T00:00:00Z", digests=(DIGEST,))
        present = Build.compile({"approval": "present"})
        assert Matcher.evaluate(present, Build.facts(approvals=(live,))).matched
        for no in (other, expired, exception):
            assert not Matcher.evaluate(present, Build.facts(approvals=(no,))).matched
        assert Matcher.evaluate(Build.compile({"approval": "absent"}), Build.facts()).matched

    def test_intelligence_facts(self) -> None:
        match = IntelMatch("known_malware", "M-1", "osv", "2026-11-01T00:00:00Z")
        advisory = IntelMatch("advisory", "GHSA-1", "osv", "2026-11-01T00:00:00Z")
        assert Matcher.evaluate(
            Build.compile({"intel.known_malware": True}), Build.facts(intel=(match,))
        ).matched
        assert not Matcher.evaluate(
            Build.compile({"intel.known_malware": True}), Build.facts(intel=(advisory,))
        ).matched
        assert Matcher.evaluate(
            Build.compile({"intel.advisory": True}), Build.facts(intel=(advisory,))
        ).matched

    def test_an_empty_predicate_always_holds(self) -> None:
        assert Matcher.evaluate((), Build.facts()).matched
