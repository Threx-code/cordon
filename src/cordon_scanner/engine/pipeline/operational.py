"""Findings about the scan itself: a file that could not be read, an archive member refused, a check
that could not run.

Every degradation produces one of these. A file that was not examined is indistinguishable in the
output from one that was examined and found clean, so coverage loss is always stated, never
inferred, and no reporting threshold may hide it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.engine.pipeline.constants import NO_RISK
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)

if TYPE_CHECKING:
    pass


class OperationalFinding:
    """Builds a finding about the scan itself."""

    @staticmethod
    def build(
        *,
        path: str,
        rule_id: str,
        message: str,
        remediation: str,
        category: Category = Category.OPERATIONAL,
        severity: Severity = Severity.INFO,
    ) -> Finding:
        """Build a finding about the scan itself.

        Every degradation produces one of these. A file that was not examined is
        indistinguishable in the output from one that was examined and found clean,
        so coverage loss must always be stated rather than inferred.
        """
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{path}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=remediation,
            # No reporting threshold may hide a finding that says coverage was
            # lost. See PolicyGate.filter_for_reporting.
            always_report=True,
            explanation=Explanation(
                summary="Reported so that reduced coverage is never silent.",
                matched_rule=rule_id,
            ),
            risk=NO_RISK,
            detector="engine",
        )


__all__ = ["OperationalFinding"]
