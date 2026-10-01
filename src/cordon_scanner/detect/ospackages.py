"""Known vulnerabilities in a container image's operating-system packages, matched through OSV.

Runs when the scan target is an image tarball and the scan is `--online`: matching sends each
package's name and version to OSV. Offline, the engine reports the inventory as not matched.
A vulnerability whose CVE is on CISA KEV or ENISA EUVD is its own rule at CRITICAL, as it is for
language dependencies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

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
from cordon_scanner.intel import exploited

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit
    from cordon_scanner.images.osv import Query, Vulnerability
    from cordon_scanner.images.packages import OsPackage
    from cordon_scanner.intel.exploited import Catalogue

PACKAGE_RULE: Final = "VULNERABLE.IMAGE.PACKAGE.001"
EXPLOITED_RULE: Final = "VULNERABLE.IMAGE.EXPLOITED.001"
UNMATCHED_RULE: Final = "OPERATIONAL.IMAGE.UNMATCHED"


def severity_of(score: float | None) -> Severity:
    """CVSS v3 qualitative bands. No score is HIGH: unrated is not the same claim as low."""
    if score is None:
        return Severity.HIGH
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


class OsPackageDetector(BaseDetector):
    id = "os-packages"
    version = "0.1.0"
    categories = frozenset({Category.VULNERABLE, Category.OPERATIONAL})
    requires = DetectorRequirements(content=False, dependencies=True, network=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return not ctx.offline and ctx.image is not None

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=PACKAGE_RULE,
                title="An image's operating-system package has a known vulnerability",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.VULNERABLE,
                detector=OsPackageDetector.id,
                message=(
                    "A package installed in this container image is named by its distribution's "
                    "advisory for the installed version, compared by the distribution's own rules."
                ),
                references=(ref.OSV,),
                remediation="Rebuild the image on a patched base, or upgrade the package in a layer.",
            ),
            DeclaredRule(
                id=EXPLOITED_RULE,
                title="An image's operating-system package has a vulnerability exploited in the wild",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.VULNERABLE,
                detector=OsPackageDetector.id,
                message=(
                    "A package installed in this container image has a vulnerability on CISA's KEV "
                    "catalogue or ENISA's EUVD exploited list."
                ),
                references=(ref.OSV, exploited.KEV_PAGE, exploited.EUVD_PAGE),
                remediation="Rebuild on a patched base now, ahead of other findings.",
            ),
            DeclaredRule(
                id=UNMATCHED_RULE,
                title="An image's packages were not all matched against advisories",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=OsPackageDetector.id,
                message="OSV could not be asked about some or all of this image's packages.",
                references=(ref.OSV,),
                remediation="Rescan when OSV is reachable.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, GraphUnit) or ctx.image is None:
            return ()
        from cordon_scanner.images import osv

        inventory = ctx.image
        source = inventory.release.advisory_source if inventory.release else None
        if source is None or not inventory.packages:
            return ()
        if source == "alas":
            return self._amazon(inventory, ctx)
        ecosystem = inventory.release.osv_ecosystem
        by_query: dict[Query, list[OsPackage]] = {}
        for package in inventory.packages:
            query = osv.Query(ecosystem, package.advisory_name, package.advisory_version)
            by_query.setdefault(query, []).append(package)
        try:
            matches = osv.match(list(by_query))
        except osv.OsvError as exc:
            return [self._unmatched(str(exc), ctx)]
        catalogue = exploited.catalogue()
        findings: list[Finding] = []
        for query, vulnerabilities in matches.by_query.items():
            for package in by_query.get(query, ()):
                for vulnerability in vulnerabilities:
                    findings.append(self._finding(package, vulnerability, catalogue, ctx))
        findings.extend(self._unmatched(problem, ctx) for problem in matches.problems)
        return findings

    def _amazon(self, inventory: Any, ctx: ScanContext) -> list[Finding]:
        from cordon_scanner.images import alas, osv

        arch = next((p.arch for p in inventory.packages if p.arch not in ("", "noarch")), "x86_64")
        try:
            advisories = alas.fetch(inventory.release.version_id, arch)
        except alas.AlasError as exc:
            return [self._unmatched(str(exc), ctx)]
        catalogue = exploited.catalogue()
        findings: list[Finding] = []
        for match in alas.affected(inventory.packages, advisories):
            advisory = match.advisory
            page = (
                "AL2023"
                if advisory.id.startswith("ALAS2023")
                else "AL2"
                if advisory.id.startswith("ALAS2-")
                else ""
            )
            vulnerability = osv.Vulnerability(
                id=advisory.id,
                summary=advisory.title,
                score=None,
                cves=frozenset(advisory.cves),
                fixed=match.fixed,
                references=(
                    f"https://alas.aws.amazon.com/{page}/{advisory.id}.html".replace(
                        "//ALAS", "/ALAS"
                    ),
                ),
                rating=advisory.severity,
            )
            findings.append(self._finding(match.package, vulnerability, catalogue, ctx))
        return findings

    def _finding(
        self,
        package: OsPackage,
        vulnerability: Vulnerability,
        catalogue: Catalogue,
        ctx: ScanContext,
    ) -> Finding:
        exploitation = catalogue.lookup(set(vulnerability.cves))
        rule_id = EXPLOITED_RULE if exploitation else PACKAGE_RULE
        rated = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        severity = (
            Severity.CRITICAL
            if exploitation
            else rated.get(vulnerability.rating, severity_of(vulnerability.score))
        )
        purl = package.purl(ctx.image.release)
        fix = (
            f" Fixed in {vulnerability.fixed}."
            if vulnerability.fixed
            else " No fixed version is published yet."
        )
        message = f"{package.name} {package.version} is named by {vulnerability.id}. {vulnerability.summary}".strip()
        message += fix
        if exploitation:
            message += " " + exploitation.describe()
        references = vulnerability.references + (exploitation.references() if exploitation else ())
        return Finding(
            rule_id=rule_id,
            category=Category.VULNERABLE,
            severity=severity,
            confidence=Confidence.HIGH,
            message=message,
            location=Location(
                path={"dpkg": "var/lib/dpkg/status", "apk": "lib/apk/db/installed"}.get(
                    package.manager, "var/lib/rpm/rpmdb.sqlite"
                ),
                package=purl,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{vulnerability.id}:{purl}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=(
                f"Upgrade {package.name} to {vulnerability.fixed} or later, usually by rebuilding on an updated base image."
                if vulnerability.fixed
                else "No fix is published; track the advisory, or remove the package if the image does not need it."
            ),
            explanation=Explanation(
                summary=f"{purl} is affected by {vulnerability.id} per OSV.", matched_rule=rule_id
            ),
            risk=ctx.scorer.score(severity, Confidence.HIGH),
            detector=self.id,
            references=references,
        )

    def _unmatched(self, problem: str, ctx: ScanContext) -> Finding:
        return Finding(
            rule_id=UNMATCHED_RULE,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=f"The image's packages were not all matched against advisories: {problem}.",
            location=Location(path="."),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{UNMATCHED_RULE}:{problem}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Rescan when OSV is reachable.",
            explanation=Explanation(summary=problem, matched_rule=UNMATCHED_RULE),
            risk=ctx.scorer.score(Severity.INFO, Confidence.CONFIRMED),
            detector=self.id,
            references=(ref.OSV,),
        )


__all__ = ["OsPackageDetector", "severity_of"]
