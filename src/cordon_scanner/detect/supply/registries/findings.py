"""A registry finding, built the one way the registry detector builds it: the declared rule's severity
and remediation, with what the registry answered as hashed evidence and the network caveat every
registry answer carries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.decide.scoring import ScoringContext
from cordon_scanner.detect.base import (
    ScanContext,
)
from cordon_scanner.foundation.models import (
    Category,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import Dependency
from cordon_scanner.detect.supply.registries.rule_declarations import DECLARED_RULES, DETECTOR

NETWORK_CAVEAT = (
    "This finding came from a live registry query. It is not reproducible from "
    "the repository alone, and rerunning the scan offline will not produce it."
)


class RegistryFinding:
    """Building the registry detector's findings."""

    @classmethod
    def finding(
        cls,
        rule_id: str,
        ctx: ScanContext,
        *,
        dependency: Dependency | None,
        detail: str,
        path: str | None = None,
        degrades_coverage: bool = False,
    ) -> Finding:
        declared = next(r for r in DECLARED_RULES if r.id == rule_id)
        if path is None:
            path = (dependency.declared_in or dependency.project or "") if dependency else ""

        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=path, line=1),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("source", "registry"),),
            ),
            remediation=declared.remediation,
            explanation=Explanation(
                summary=detail,
                matched_rule=rule_id,
                escalations=(NETWORK_CAVEAT,),
            ),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=DETECTOR,
            always_report=declared.category is Category.OPERATIONAL,
            degrades_coverage=degrades_coverage,
        )


__all__ = ["NETWORK_CAVEAT", "RegistryFinding"]
