"""The facts a policy predicate reads, and the matcher that reads them (design spec 5.3 step 1).

`Facts` is everything `decide()` was given, with the one derived fact (whether an active approval covers this
digest in this scope) computed once. `Matcher.evaluate` answers whether a compiled predicate holds, and which
findings made it hold.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet, FindingFact
from cordon_scanner.decide.decision.predicates import Condition, Fields, Match, PredicateEvaluator


@dataclass(frozen=True, slots=True)
class Facts:
    artifact: ArtifactRef
    context: Context
    evidence: EvidenceSet
    clock: datetime
    approved: bool = False

    @classmethod
    def of(
        cls, artifact: ArtifactRef, context: Context, evidence: EvidenceSet, clock: datetime
    ) -> Facts:
        """The facts of a call; `approved` is true when an active approval (not an exception) lists this
        digest and speaks for this scope."""
        approved = any(
            item.kind != "exception"
            and item.active(clock)
            and item.covers(artifact.digest, context.scope_path)
            for item in evidence.approvals
        )
        return cls(artifact, context, evidence, clock, approved)

    def value(self, field: str) -> Any:
        """The value of a non-finding field, or `None` when it is not known."""
        found = self._subject(field)
        if found is not None or field != "approval":
            return found
        return "absent"

    def _subject(self, field: str) -> Any:
        artifact, context, evidence = self.artifact, self.context, self.evidence
        provenance = evidence.provenance
        table = {
            "subject.kind": artifact.kind,
            "subject.ecosystem": artifact.ecosystem,
            "subject.namespace": artifact.namespace,
            "subject.tags": artifact.tags,
            "subject.id": artifact.subject_id,
            "artifact.digest": artifact.digest,
            "version.age_days": artifact.age_days(self.clock),
            "provenance.slsa_level": (provenance.slsa_level if provenance.verified else 0)
            if provenance
            else None,
            "signature.signer": provenance.signer if provenance and provenance.verified else None,
            "approval": "present" if self.approved else None,
            "context.point": context.point,
            "context.environment": context.environment,
            "context.relation": context.relation,
            "context.actor": context.actor,
            "intel.known_malware": bool(evidence.known_malware()),
            "intel.advisory": any(
                item.kind == "advisory" and not item.withdrawn for item in evidence.intel
            ),
        }
        return table.get(field)

    @staticmethod
    def finding_value(finding: FindingFact, field: str) -> Any:
        return {
            "finding.rule_id": finding.rule_id,
            "finding.category": finding.category,
            "finding.severity": finding.severity,
            "finding.confidence": finding.confidence,
            "finding.domain": finding.domain,
        }[field]


class Matcher:
    """Whether a compiled predicate holds."""

    @staticmethod
    def evaluate(conditions: tuple[Condition, ...], facts: Facts) -> Match:
        """Every non-finding condition must hold; the finding conditions must all hold for some one finding
        (a rule on `finding.category` and `finding.confidence` means a finding that is both)."""
        about_findings = [item for item in conditions if Fields.TABLE[item.field].is_finding]
        for item in conditions:
            if not Fields.TABLE[item.field].is_finding and not PredicateEvaluator.holds(
                item, Fields.TABLE[item.field], facts.value(item.field)
            ):
                return Match(False)
        if not about_findings:
            return Match(True)
        hits = tuple(
            finding
            for finding in facts.evidence.findings
            if all(
                PredicateEvaluator.holds(
                    item, Fields.TABLE[item.field], Facts.finding_value(finding, item.field)
                )
                for item in about_findings
            )
        )
        return Match(bool(hits), hits)


__all__ = ["Facts", "Matcher"]
