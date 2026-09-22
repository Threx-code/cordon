"""Matches resolved dependencies against the advisory database.

A graph detector: it runs once against the whole dependency set rather than per
file, because the question it answers -- "is this exact package at this exact
version known to be bad?" -- is about the resolved graph and not about any
file's contents.

`MALWARE.DEPENDENCY.KNOWN.001` and an exact-list `VULNERABLE.DEPENDENCY.KNOWN.001`
match are the only findings that emit `Confidence.CONFIRMED`. The model reserves
that level for "an exact package-and-version match against the
threat-intelligence database", and an identity match against a recorded incident
is the one thing that earns it: there is no inference, no heuristic and no
pattern that might mean something else. A range-based vulnerability match
(`Advisory.is_range`) is a small inference on top of identity -- does this
version fall between these two? -- so it is reported at `HIGH` instead. Every
other detector reasons from behaviour and tops out there too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.intel.advisories import Advisory, AdvisoryDatabase, tampered_files

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

MALICIOUS_RULE = "MALWARE.DEPENDENCY.KNOWN.001"
VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"
DATABASE_AGE_RULE = "OPERATIONAL.ADVISORY.DATABASE_AGE"
DATABASE_SCOPE_RULE = "OPERATIONAL.ADVISORY.DATABASE_SCOPE"
TAMPERED_RULE = "OPERATIONAL.ADVISORY.TAMPERED"

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

STALE_AFTER_DAYS = 45
"""How old the bundled snapshot can get before the coverage note escalates
from an FYI to something worth acting on. Between Trivy's 24-hour default (a
DB it refreshes on every run) and a PyPI release cadence measured in weeks --
this project's own data is refreshed weekly by `refresh-advisories.yml` but
only *shipped* at release time, so a few weeks old is normal, not stale."""


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

        # Before anything else about coverage. A file refused for a digest
        # mismatch has already removed part of the database, and the count that
        # made it past the empty check above says nothing about which part.
        refused = tampered_files()
        if refused:
            findings.append(
                self.operational(
                    path=".",
                    message=(
                        f"{len(refused)} advisory data file(s) do not match the digest "
                        f"manifest shipped with them and were not loaded: "
                        f"{', '.join(refused)}. Dependencies were checked against a "
                        f"database missing those ecosystems entirely."
                    ),
                    detail="advisories",
                    rule_id=TAMPERED_RULE,
                )
            )

        age_note = self._database_age_note()
        if age_note is not None:
            findings.append(age_note)

        scope_note = self._database_scope_note()
        if scope_note is not None:
            findings.append(scope_note)

        for dependency in unit.dependencies:
            for advisory in self._database.matching(
                dependency.ecosystem, dependency.name, dependency.version
            ):
                findings.append(self._finding(dependency, advisory, ctx))
        return findings

    def _database_age_note(self) -> Finding | None:
        """Surface it only when the bundled advisory data has gone stale.

        A note on every single scan -- fresh or not -- is a line every
        consumer of the report has to learn to ignore, which is the failure
        mode this project spends real effort avoiding elsewhere (see
        `STATUS.md`'s noise-reduction work). Trivy's and Grype's own DB-age
        banners are informational chrome outside the finding list; this
        project's findings ARE the report, so the equivalent is to only speak
        up when the age is actually something to act on.
        """
        meta = self._database.meta
        if not meta.built_at:
            return None
        from datetime import UTC, datetime

        try:
            built = datetime.fromisoformat(meta.built_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        age_days = (datetime.now(UTC) - built).days
        if age_days <= STALE_AFTER_DAYS:
            return None
        message = (
            f"Advisory data is {age_days} day(s) old (built {meta.built_at}, "
            f"{meta.record_count} record(s) from {', '.join(meta.sources) or 'bundled sources'}), "
            f"beyond the {STALE_AFTER_DAYS}-day freshness window this build expects. "
            f"Run `cordon-scanner advisories sync` for current data."
        )
        return self.operational(
            path=".",
            message=message,
            detail="advisories",
            rule_id=DATABASE_AGE_RULE,
        )

    def _database_scope_note(self) -> Finding | None:
        """Say what the database does not contain, whenever it is a subset.

        The release bundles malicious entries and high/critical vulnerabilities
        and drops the rest, which is a deliberate size trade -- and a user
        reading a clean report is entitled to know that low and medium
        advisories were never consulted. This was previously a clause inside the
        staleness note, so a database that was filtered *and current* -- the
        normal case for the whole period after a release -- said nothing at all,
        and a scan that had checked part of the data looked like one that had
        checked all of it.

        Reported at INFO and once per scan, which is what the `OPERATIONAL`
        category is for: it describes the scan rather than the code.
        """
        meta = self._database.meta
        if not meta.filtered:
            return None
        return self.operational(
            path=".",
            message=(
                f"The bundled advisory database is the malicious + high/critical "
                f"subset, not the full set: {meta.record_count:,} record(s) from "
                f"{', '.join(meta.sources) or 'bundled sources'}. Low- and "
                f"medium-severity advisories were not consulted, so a dependency "
                f"clean here may still be named by one."
            ),
            detail="advisories",
            rule_id=DATABASE_SCOPE_RULE,
        )

    def _finding(self, dependency: Dependency, advisory: Advisory, ctx: ScanContext) -> Finding:
        malicious = advisory.malicious
        rule_id = MALICIOUS_RULE if malicious else VULNERABLE_RULE
        confidence = Confidence.HIGH if advisory.is_range else Confidence.CONFIRMED
        if malicious:
            severity = Severity.CRITICAL
        else:
            severity = _SEVERITY_MAP.get(advisory.severity.lower(), Severity.HIGH)

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

        if advisory.is_range:
            match_summary = (
                f"{dependency.purl} falls within the affected range "
                f"{advisory.introduced or '0'}-{advisory.fixed or advisory.last_affected or '?'} "
                f"named by {advisory.identifier or 'an advisory'}."
            )
        else:
            match_summary = (
                f"{dependency.purl} matches {advisory.identifier or 'an advisory'} "
                f"exactly, by ecosystem, name and version."
            )

        return Finding(
            rule_id=rule_id,
            category=Category.MALICIOUS if malicious else Category.VULNERABLE,
            severity=severity,
            # CONFIRMED for an identity match against a recorded incident, with
            # no inference in between; HIGH for a range match, which adds one
            # inferential step -- does this version fall between these two? --
            # on top of that identity. See `Advisory.is_range`.
            confidence=confidence,
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
                summary=match_summary,
                matched_rule=rule_id,
            ),
            risk=ctx.scorer.score(severity, confidence),
            detector=self.id,
            references=(advisory.reference,) if advisory.reference else (),
            capabilities=(),
        )


__all__ = ["AdvisoryDetector"]
