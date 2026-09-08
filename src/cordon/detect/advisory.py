"""Matches resolved dependencies against the advisory database.

A graph detector: it runs once against the whole dependency set rather than per
file, because the question it answers -- "is this exact package at this exact
version known to be bad?" -- is about the resolved graph and not about any
file's contents.

This is the only detector that emits `Confidence.CONFIRMED`. The model reserves
that level for "an exact package-and-version match against the
threat-intelligence database", and an identity match against a recorded incident
is the one thing that earns it: there is no inference, no heuristic and no
pattern that might mean something else. Every other detector reasons from
behaviour and tops out at `HIGH`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon.core.models import (
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon.detect.catalogue import DeclaredRule
from cordon.intel.advisories import Advisory, AdvisoryDatabase

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import ScanContext, Unit

MALICIOUS_RULE = "MALWARE.DEPENDENCY.KNOWN.001"
VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"


class AdvisoryDetector(BaseDetector):
    """Reports dependencies that are known to be malicious or vulnerable."""

    id = "advisory"
    version = "0.1.0"
    categories = frozenset({Category.MALICIOUS, Category.VULNERABLE})
    requires = DetectorRequirements(content=False, dependencies=True)

    def __init__(self, database: AdvisoryDatabase | None = None) -> None:
        # `is None`, not `or`. An AdvisoryDatabase is falsy when empty, so
        # `database or bundled()` silently replaced a deliberately empty
        # database -- an organisation stating "these are the only advisories I
        # act on" got the shipped list instead, which is the substitution this
        # project argues against everywhere else.
        self._database = AdvisoryDatabase.bundled() if database is None else database

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=MALICIOUS_RULE,
                title="Dependency is a known-malicious release",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.MALICIOUS,
                detector=AdvisoryDetector.id,
                remediation=(
                    "Remove the version and treat every machine that installed it as compromised."
                ),
            ),
            DeclaredRule(
                id=VULNERABLE_RULE,
                title="Dependency has a known vulnerability",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=Category.VULNERABLE,
                detector=AdvisoryDetector.id,
                remediation="Upgrade to a version the advisory does not name.",
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        """Always applicable, even with nothing to match against.

        Returning False for an empty database made `--advisories empty.json`
        remove the whole layer with no notice and exit 0, while a
        known-malicious dependency sat in the lockfile. A detector that declines
        to run is a coverage loss, and every other coverage loss in this project
        is reported.
        """
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit):
            return ()

        findings: list[Finding] = []

        if not len(self._database):
            return (
                self.operational(
                    path=".",
                    message=(
                        "The advisory database is empty, so no dependency was checked "
                        "against it. Known-malicious and known-vulnerable packages "
                        "will not be reported."
                    ),
                    detail="advisories",
                    rule_id="OPERATIONAL.ADVISORY.EMPTY",
                ),
            )

        for dependency in unit.dependencies:
            for advisory in self._database.matching(
                dependency.ecosystem, dependency.name, dependency.version
            ):
                findings.append(self._finding(dependency, advisory, ctx))
        return findings

    def _finding(self, dependency: Dependency, advisory: Advisory, ctx: ScanContext) -> Finding:
        malicious = advisory.malicious
        rule_id = MALICIOUS_RULE if malicious else VULNERABLE_RULE
        severity = Severity.CRITICAL if malicious else Severity.HIGH

        if malicious:
            message = (
                f"{dependency.name} {dependency.version} is a known-malicious release. "
                f"{advisory.summary} This is an exact match against a recorded "
                f"incident, not a heuristic."
            )
            remediation = (
                f"Remove {dependency.name} {dependency.version} and pin a version the "
                f"advisory does not name. Treat every machine that installed it as "
                f"compromised, and rotate the credentials reachable from it, starting "
                f"with registry publish tokens."
            )
        else:
            message = (
                f"{dependency.name} {dependency.version} is named by "
                f"{advisory.identifier or 'an advisory'}. {advisory.summary}"
            )
            remediation = "Upgrade to a version the advisory does not name."

        return Finding(
            rule_id=rule_id,
            category=Category.MALICIOUS if malicious else Category.VULNERABLE,
            severity=severity,
            # The one place CONFIRMED is warranted: an identity match against a
            # recorded incident, with no inference in between.
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{advisory.identifier}:{dependency.purl}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=(
                    f"{dependency.purl} matches {advisory.identifier or 'an advisory'} "
                    f"exactly, by ecosystem, name and version."
                ),
                matched_rule=rule_id,
            ),
            risk=ctx.scorer.score(severity, Confidence.CONFIRMED),
            detector=self.id,
            references=(advisory.reference,) if advisory.reference else (),
            capabilities=(),
        )


__all__ = ["AdvisoryDetector"]
