"""Dependencies whose names are documented AI hallucinations (slopsquatting).

Offline: a dependency's name is checked against the bundled, feed-updated list in
`intel.hallucinated`. Online, the registry detector adds the broader signal: a declared dependency
the public registry does not have at all (`SUSPECT.DEPENDENCY.UNREGISTERED.001`).
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references as ref
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
from cordon_scanner.intel.registry import HallucinatedPackages

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit
    from cordon_scanner.foundation.results import Dependency

RULE = "SUSPECT.DEPENDENCY.HALLUCINATED.001"
BUNDLED_RULE: Final = "SUSPECT.DEPENDENCY.HALLUCINATED.BUNDLED.001"
"""The same name in a record installing the package does not install: info, after the verdict and
never gating (`DependencyDetector`'s docstring has the rule for which checks have such a twin)."""


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
            DeclaredRule(
                id=BUNDLED_RULE,
                title="A dependency the package bundles but does not install is a documented AI hallucination",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=SlopsquatDetector.id,
                message=(
                    "Only a nested or vendored file in this package records the dependency, and its "
                    "name is one AI coding assistants are documented to invent. Installing the "
                    "package does not install it; building the subdirectory that records it does."
                ),
                references=(ref.PACKAGE_HALLUCINATION,),
                remediation="If that subdirectory is built, replace the name with the package it was reaching for.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()
        return self._findings(unit.dependencies, ctx)

    def not_installed(self, dependencies: Iterable[Dependency], ctx: ScanContext) -> list[Finding]:
        """Records installing the target does not install (`installed=False`) whose name is on
        the list: SUSPECT.DEPENDENCY.HALLUCINATED.BUNDLED, at info, naming the file."""
        return [
            replace(
                finding,
                rule_id=BUNDLED_RULE,
                severity=Severity.INFO,
                message=f"Not installed with this package: only {finding.location.path} records it. "
                + finding.message,
                explanation=replace(finding.explanation, matched_rule=BUNDLED_RULE),
                risk=ctx.scorer.score(Severity.INFO, finding.confidence),
            )
            for finding in self._findings([d for d in dependencies if not d.installed], ctx)
        ]

    def _findings(self, dependencies: Iterable[Dependency], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for dependency in dependencies:
            match = HallucinatedPackages.lookup(dependency.ecosystem, dependency.name)
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


__all__ = ["BUNDLED_RULE", "SlopsquatDetector"]
