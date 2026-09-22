"""Flagging a dependency's declared license, where one is known offline.

A graph detector, the same shape as `detect/advisory.py`: it runs once
against the whole resolved dependency set, because "what license does this
depend on" is a question about the graph, not about any file's contents.

Reports only what `intel/licenses.py` classifies as copyleft or weak
copyleft. A permissive license is not newsworthy -- reporting one on every
scan would be exactly the noise this project's own enterprise-benchmark work
(`STATUS.md`) spent real effort removing elsewhere -- and an unknown or
absent license is reported nowhere near as confidently as "this dependency
has no license", which this detector never claims: `Dependency.license` being
`None` means the lockfile format did not carry the data offline, not that the
dependency has none. See `intel/licenses.py`'s module docstring for what
"copyleft" means here: a fact about the identifier, not a legal conclusion
about how this project uses it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core import references
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
from cordon_scanner.intel.licenses import LicenseCategory, classify, normalize

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import ScanContext, Unit

COPYLEFT_RULE = "POLICY.LICENSE.COPYLEFT.001"
WEAK_COPYLEFT_RULE = "POLICY.LICENSE.WEAK_COPYLEFT.001"
NETWORK_COPYLEFT_RULE = "POLICY.LICENSE.NETWORK_COPYLEFT.001"

_SEVERITY = {
    LicenseCategory.NETWORK_COPYLEFT: Severity.MEDIUM,
    LicenseCategory.COPYLEFT: Severity.MEDIUM,
    LicenseCategory.WEAK_COPYLEFT: Severity.LOW,
}
_RULE_ID = {
    LicenseCategory.NETWORK_COPYLEFT: NETWORK_COPYLEFT_RULE,
    LicenseCategory.COPYLEFT: COPYLEFT_RULE,
    LicenseCategory.WEAK_COPYLEFT: WEAK_COPYLEFT_RULE,
}


class LicenseDetector(BaseDetector):
    """Reports dependencies under a copyleft or weak-copyleft license."""

    id = "license"
    version = "0.1.0"
    categories = frozenset({Category.POLICY})
    requires = DetectorRequirements(content=False, dependencies=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=NETWORK_COPYLEFT_RULE,
                title="Dependency is under a network-copyleft license",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=LicenseDetector.id,
                message=(
                    "A dependency is licensed under terms that treat providing access over a "
                    "network as distribution. A service that never ships a binary can still "
                    "trigger the obligation."
                ),
                remediation=(
                    "A network-copyleft license (AGPL, SSPL, OSL, EUPL) reaches "
                    "software offered as a service, where ordinary copyleft's "
                    "distribution trigger does not. Confirm this dependency's "
                    "obligations fit a hosted deployment, or replace it."
                ),
                references=(references.SPDX,),
            ),
            DeclaredRule(
                id=COPYLEFT_RULE,
                title="Dependency is under a copyleft license",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=LicenseDetector.id,
                message=(
                    "A dependency is licensed under terms that extend to work derived from it. "
                    "Whether that matters depends on how this project is distributed, which is "
                    "a decision for whoever owns the licensing rather than for a scanner."
                ),
                remediation=(
                    "Confirm the license's obligations fit how this dependency is "
                    "linked and distributed, or replace it with a permissively "
                    "licensed alternative."
                ),
                references=(references.SPDX,),
            ),
            DeclaredRule(
                id=WEAK_COPYLEFT_RULE,
                title="Dependency is under a weak-copyleft license",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=LicenseDetector.id,
                message=(
                    "A dependency is licensed under terms that extend to modifications of that "
                    "component but not to the work that links it. The obligation is narrower "
                    "than full copyleft and it is not absent."
                ),
                remediation=(
                    "Weak-copyleft obligations are usually file- or "
                    "library-scoped rather than whole-program; confirm the "
                    "linking model this dependency is used under still qualifies."
                ),
                references=(references.SPDX,),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()

        findings: list[Finding] = []
        for dependency in unit.dependencies:
            declared_license = dependency.license
            if not declared_license:
                continue
            category = classify(declared_license)
            if category not in _RULE_ID:
                continue
            findings.append(self._finding(dependency, declared_license, category, ctx))
        return findings

    @staticmethod
    def _remediation(category: LicenseCategory) -> str:
        if category is LicenseCategory.NETWORK_COPYLEFT:
            return (
                "A network-copyleft license reaches software offered over a network, "
                "not only software that is distributed. Confirm its obligations fit a "
                "hosted deployment, or replace it with a permissively licensed alternative."
            )
        if category is LicenseCategory.COPYLEFT:
            return (
                "Confirm the license's obligations fit how this dependency is linked "
                "and distributed, or replace it with a permissively licensed alternative."
            )
        return (
            "Weak-copyleft obligations are usually file- or library-scoped; confirm the "
            "linking model this dependency is used under still qualifies."
        )

    def _finding(
        self,
        dependency: Dependency,
        declared_license: str,
        category: LicenseCategory,
        ctx: ScanContext,
    ) -> Finding:
        rule_id = _RULE_ID[category]
        severity = _SEVERITY[category]
        normalized = normalize(declared_license) or declared_license
        label = {
            LicenseCategory.NETWORK_COPYLEFT: "network-copyleft",
            LicenseCategory.COPYLEFT: "copyleft",
            LicenseCategory.WEAK_COPYLEFT: "weak-copyleft",
        }[category]

        message = (
            f"{dependency.name}{f' {dependency.version}' if dependency.version else ''} "
            f"declares {declared_license!r} ({normalized}), a {label} license."
        )

        return Finding(
            rule_id=rule_id,
            category=Category.POLICY,
            severity=severity,
            confidence=Confidence.MEDIUM,
            message=message,
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{dependency.purl}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("license", declared_license),),
            ),
            remediation=self._remediation(category),
            explanation=Explanation(
                summary=message,
                matched_rule=rule_id,
            ),
            risk=ctx.scorer.score(severity, Confidence.MEDIUM),
            detector=self.id,
            references=(),
            capabilities=(),
        )


__all__ = ["COPYLEFT_RULE", "WEAK_COPYLEFT_RULE", "LicenseDetector"]
