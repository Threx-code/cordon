"""Dependencies whose names are documented AI hallucinations (slopsquatting).

Offline: a dependency's name is checked against the bundled, feed-updated list in
`intel.hallucinated`. Online, the registry detector adds the broader signal: a declared dependency
the public registry does not have at all (`SUSPECT.DEPENDENCY.UNREGISTERED.001`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core import references as ref
from cordon_scanner.core.models import (
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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.intel import hallucinated

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

RULE = "SUSPECT.DEPENDENCY.HALLUCINATED.001"


class SlopsquatDetector(BaseDetector):
    id = "slopsquat"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=False, dependencies=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=RULE,
                title="A dependency's name is a documented AI hallucination",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=SlopsquatDetector.id,
                message=(
                    "This dependency's name is one AI coding assistants are documented to invent for a "
                    "real package, and which has been registered by someone other than that package's "
                    "maintainers. Following the suggestion installs whatever they published."
                ),
                references=(ref.PACKAGE_HALLUCINATION,),
                remediation="Replace it with the package the suggestion was reaching for, named in the finding.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()
        findings: list[Finding] = []
        for dependency in unit.dependencies:
            match = hallucinated.lookup(dependency.ecosystem, dependency.name)
            if match is None:
                continue
            message = (
                f"{dependency.name} is a name AI assistants invent; the real package is "
                f"{match.intended or 'a different one'}. {match.note}"
            ).strip()
            findings.append(
                Finding(
                    rule_id=RULE,
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message=message,
                    location=Location(
                        path=dependency.declared_in or dependency.project or ".",
                        package=dependency.purl,
                        project=dependency.project,
                    ),
                    evidence=Evidence(
                        kind=EvidenceKind.GRAPH,
                        match_hash=Evidence.hash_bytes(f"{RULE}:{dependency.purl}".encode()),
                        redaction=RedactionMode.NONE,
                    ),
                    remediation=f"Replace {dependency.name} with {match.intended or 'the package it was meant to be'}.",
                    explanation=Explanation(
                        summary=f"{dependency.name} is on the hallucinated-name list.",
                        matched_rule=RULE,
                    ),
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                    detector=self.id,
                    references=(ref.PACKAGE_HALLUCINATION,),
                )
            )
        return findings


__all__ = ["SlopsquatDetector"]
