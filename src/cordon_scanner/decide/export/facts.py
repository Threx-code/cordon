"""The facts of one call, as the JSON document an exported policy is evaluated over (row BP-6-5).

`ExportFacts.of` runs the library's own fact derivation (`Facts`, `Completeness`'s conditions) and writes down what an exported policy
reads: the value of every non-finding field the call knows, the findings with their ranks, the hard stops, and which shortfalls
of evidence the call has. A field the call does not know is absent, and a condition on an absent field holds for nothing, as in
`decide()`.

```
{ "environment": "production",
  "values":   { "subject.kind": "package", "version.age_days": 2, ... },
  "findings": [ { "rule_id", "category", "severity", "confidence", "domain", "severity_rank", "confidence_rank" } ],
  "hard_stop": false,
  "shortfalls": { "required_missing": false, "unresolved": false, "incomplete": false, "gaps": false,
                  "bundle_expired": false, "intel_stale": false, "provenance_unverified": false } }
```
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cordon_scanner.decide.decision.evidence import FindingFact
from cordon_scanner.decide.decision.facts import Facts
from cordon_scanner.decide.decision.pipeline import Completeness
from cordon_scanner.decide.decision.predicates import Fields
from cordon_scanner.decide.decision.records import Instants
from cordon_scanner.decide.export.table import ExportUnsupported

if TYPE_CHECKING:
    from datetime import datetime

    from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet
    from cordon_scanner.decide.decision.table import CompiledPolicy


class ExportFacts:
    @classmethod
    def of(
        cls,
        artifact: ArtifactRef,
        context: Context,
        evidence: EvidenceSet,
        clock: datetime,
        policy: CompiledPolicy,
    ) -> dict[str, Any]:
        if evidence.approvals:
            raise ExportUnsupported(
                "not exportable: the evidence carries an approval or exception; ask decide()"
            )
        facts = Facts.of(artifact, context, evidence, clock)
        values: dict[str, Any] = {}
        for name, spec in Fields.TABLE.items():
            if spec.is_finding or name == "approval":
                continue
            found = facts.value(name)
            if found is None:
                continue
            values[name] = list(found) if isinstance(found, tuple) else found
        defaults = policy.defaults
        expired = policy.expires_at is not None and Instants.parse(policy.expires_at) <= clock
        return {
            "environment": context.environment,
            "values": values,
            "findings": [
                cls._finding(item)
                for item in sorted(evidence.findings, key=lambda each: each.sort_key())
            ],
            "hard_stop": bool(
                evidence.known_malware()
                or evidence.revoked
                or evidence.integrity_ok is False
                or evidence.kill_listed
            ),
            "shortfalls": {
                "required_missing": bool(evidence.required_missing),
                "unresolved": bool(evidence.unresolved),
                "incomplete": not evidence.complete,
                "gaps": bool(evidence.gaps),
                "bundle_expired": expired
                or cls._over(context.bundle_age_s, defaults.bundle_max_age_s),
                "intel_stale": cls._over(context.intel_age_s, defaults.max_intel_age_s),
                "provenance_unverified": bool(
                    evidence.provenance is not None
                    and not evidence.provenance.verified
                    and Completeness.reads_provenance(policy)
                ),
            },
        }

    @staticmethod
    def _finding(item: FindingFact) -> dict[str, Any]:
        return {
            "rule_id": item.rule_id,
            "category": item.category,
            "severity": item.severity,
            "confidence": item.confidence,
            "domain": item.domain,
            "severity_rank": FindingFact.SEVERITIES.index(item.severity),
            "confidence_rank": FindingFact.CONFIDENCES.index(item.confidence),
        }

    @staticmethod
    def _over(age: int | None, limit: int | None) -> bool:
        return age is not None and limit is not None and age > limit


__all__ = ["ExportFacts"]
