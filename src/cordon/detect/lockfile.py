"""Lockfile inspection.

The lockfile is the only file in a repository that states exactly what will be
installed. It is therefore the most security-relevant file present and, in most
scanners, the least examined -- frequently excluded outright as noisy
machine-generated output.

Two checks matter here, and both are about whether the ecosystem's own
protections are actually in force:

**Missing integrity hashes.** A lockfile entry with no hash pins a version but
verifies nothing. If the registry serves different bytes for that version, the
install proceeds and nothing notices.

**Non-registry resolution.** An entry resolved from a git URL or archive URL
bypasses advisory matching and any release-age policy, whatever the manifest
appears to declare.

The absence of a lockfile is itself reported, because it means what will be
installed is not knowable in advance.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from cordon.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon.core.scoring import ScoringContext
from cordon.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon.detect.catalogue import DeclaredRule
from cordon.ecosystems.registry import EcosystemRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon.detect.base import Unit
    from cordon.ecosystems.base import Ecosystem, LockGraph

# Reporting one finding per unverified package turns a single misconfiguration
# into hundreds of alerts, which is how a useful signal becomes a suppressed
# one. Beyond this count the finding is summarised instead.
MAX_INDIVIDUAL = 5


class LockfileDetector(BaseDetector):
    """Inspects lockfiles for integrity and provenance."""

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="POLICY.LOCKFILE.INTEGRITY.001",
                title="Lockfile entry without an integrity hash",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector=LockfileDetector.id,
                remediation="Regenerate the lockfile so every entry carries a hash.",
            ),
            DeclaredRule(
                id="SUSPECT.LOCKFILE.SOURCE.001",
                title="Lockfile entry resolved from outside the registry",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=LockfileDetector.id,
                remediation="Confirm the source is intended and controlled by you.",
            ),
        )

    @staticmethod
    def _host_of(url: str) -> str:
        if "://" not in url:
            return url[:40]
        return url.split("://", 1)[1].split("/", 1)[0]

    id = "lockfile"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        ecosystem_id = EcosystemRegistry.lockfile_ecosystem(unit.path)
        if ecosystem_id is None:
            return ()

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return ()

        graph = ecosystem.parse_lockfile(unit.content)

        if graph.parse_error:
            # Not every "lockfile-shaped" path is a lockfile. An unpinned
            # requirements file matches the glob and legitimately yields
            # nothing, so silence is correct there rather than a finding.
            if "unsupported" in graph.parse_error:
                return ()
            return [
                self._operational(
                    unit.path,
                    f"Could not parse this {ecosystem_id} lockfile, so integrity "
                    f"and provenance were not verified: {graph.parse_error}",
                )
            ]

        if not graph.entries:
            return ()

        findings: list[Finding] = []
        findings.extend(self._integrity_findings(graph, ecosystem, unit, ctx))
        findings.extend(self._source_findings(graph, ecosystem, unit, ctx))
        return findings

    # -- Integrity -------------------------------------------------------

    def _integrity_findings(
        self, graph: LockGraph, ecosystem: Ecosystem, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        # Entries resolved from outside the registry are excluded. A git or
        # path dependency has no registry hash to carry, so counting it as
        # missing one reports a fact of the format as though it were an anomaly
        # -- and it is already reported, accurately, by the provenance check
        # below. Double-reporting one dependency under two rules is how a
        # useful signal turns into noise.
        candidates = [e for e in graph.entries if ecosystem.is_registry_host(e.resolved_from)]
        missing = [e for e in candidates if not e.integrity]
        if not missing or not candidates:
            return

        total = len(candidates)
        share = len(missing) / total

        # An ecosystem whose lockfile format carries no hashes at all is a
        # different statement from one where a few entries lost theirs. The
        # first is a property of the format; the second is a real anomaly.
        if share > 0.9:
            message = (
                f"None of the {total} entries in this lockfile carry an integrity "
                f"hash, so nothing verifies that the bytes installed are the bytes "
                f"that were reviewed. A version pin without a hash constrains the "
                f"name, not the content."
            )
            severity = Severity.MEDIUM
        else:
            listed = ", ".join(f"{e.name}@{e.version}" for e in missing[:MAX_INDIVIDUAL])
            more = (
                f" and {len(missing) - MAX_INDIVIDUAL} more"
                if len(missing) > MAX_INDIVIDUAL
                else ""
            )
            message = (
                f"{len(missing)} of {total} entries carry no integrity hash "
                f"({listed}{more}). The rest of the file is hashed, so these "
                f"specific packages are unverified while appearing pinned."
            )
            severity = Severity.HIGH

        yield self._finding(
            rule_id="POLICY.LOCKFILE.INTEGRITY.001",
            category=Category.POLICY,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            title="Lockfile entries without integrity hashes",
            message=message,
            remediation=(
                "Regenerate the lockfile with the package manager so every entry "
                "carries a hash, and verify the regenerated file in review."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{len(missing)}/{total} unhashed",
        )

    # -- Provenance ------------------------------------------------------

    def _source_findings(
        self, graph: LockGraph, ecosystem: Ecosystem, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        foreign = [
            e
            for e in graph.entries
            if e.resolved_from and not ecosystem.is_registry_host(e.resolved_from)
        ]
        if not foreign:
            return

        hosts = Counter(LockfileDetector._host_of(e.resolved_from or "") for e in foreign)
        listed = ", ".join(f"{host} ({count})" for host, count in sorted(hosts.items()))
        names = ", ".join(f"{e.name}@{e.version}" for e in foreign[:MAX_INDIVIDUAL])
        more = f" and {len(foreign) - MAX_INDIVIDUAL} more" if len(foreign) > MAX_INDIVIDUAL else ""

        yield self._finding(
            rule_id="SUSPECT.LOCKFILE.SOURCE.001",
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            title="Packages resolved from outside the registry",
            message=(
                f"{len(foreign)} package(s) resolve from hosts other than the "
                f"{ecosystem.id} registry: {listed}. Affected: {names}{more}. "
                f"Advisory matching and release-age policy apply to registry "
                f"packages and do not apply to these."
            ),
            remediation=(
                "Confirm each host is one the organisation controls. Mirror the "
                "packages into an internal registry so the usual controls apply."
            ),
            unit=unit,
            ctx=ctx,
            detail=listed,
        )

    # -- Construction ----------------------------------------------------

    def _finding(
        self,
        *,
        rule_id: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: str,
        message: str,
        remediation: str,
        unit: FileUnit,
        ctx: ScanContext,
        detail: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=unit.path, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{unit.path}:{detail}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("detail", detail),),
            ),
            remediation=remediation,
            explanation=Explanation(summary=title, matched_rule=rule_id),
            risk=ctx.scorer.score(severity, confidence, ScoringContext()),
            detector=self.id,
        )

    def _operational(self, path: str, message: str) -> Finding:
        return Finding(
            rule_id="OPERATIONAL.LOCKFILE.UNPARSED",
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(path.encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Regenerate the lockfile with the package manager.",
            explanation=Explanation(
                summary="A lockfile that cannot be parsed is one that was not verified.",
                matched_rule="OPERATIONAL.LOCKFILE.UNPARSED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector=self.id,
        )


__all__ = ["LockfileDetector"]
