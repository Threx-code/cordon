"""An advisory finding, built the one way the advisory detector builds it.

A dependency matched to an advisory -- its severity from the advisory's own score where it has one,
the versions that fix it, the references, the evidence of which version is installed and where --
and the two findings an advisory database states about a name rather than a version: a package
removed from its registry as malicious in every version, and a name taken over with a placeholder
left in its place."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Scope,
    Severity,
)
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.advisories import exploited
from cordon_scanner.intel.advisories.advisories import Advisory
from cordon_scanner.intel.registries.removed import RemovedNames

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.detect.base import ScanContext

TEST_FIXTURE_SEGMENTS = frozenset(
    {"test", "tests", "testing", "fixture", "fixtures", "testdata", "__tests__", "spec"}
)
"""Directories that hold a test's own material, by their whole name."""

MALICIOUS_RULE = "MALWARE.DEPENDENCY.KNOWN.001"

PLACEHOLDER_RULE = "POLICY.DEPENDENCY.SECURITY_PLACEHOLDER.001"

REMOVED_RULE = "SUSPECT.DEPENDENCY.REMOVED_NAME.001"
"""A range over a name whose every version is malicious, and which the registry no longer serves
(`RemovedNames`): an install fails rather than installing the malware, and a re-registration of the
name would deliver whatever its new owner publishes. Medium: a risk worth removing, not a block."""

SECURITY_PLACEHOLDER = re.compile(r"^\d+\.\d+\.\d+-security$")
"""npm's tombstone for a package name its security team took over.

When a name is used to publish malware, npm removes the releases and publishes
an empty package at `0.0.1-security` in their place. The advisory that covers
the incident names the whole package -- `introduced: 0`, no fixed version --
so it matches the placeholder too, and the placeholder is what a project has
AFTER the problem was dealt with.

Measured against `Azure/azure-quickstart-templates`, which pins
`http@0.0.1-security` in a Jenkins example: the scan told Microsoft their build
carried a known-malicious release and to treat every machine that installed it
as compromised. What it carries is npm's own empty package, resolved from the
registry with an integrity hash. The advisory is right about the name and the
conclusion is not available about this version.

Deliberately exact: a prerelease of `security` on a three-part version, which
is the form npm publishes and not something a project picks. `1.2.3-security.1`
or `2.0.0-security-fix` is somebody's own release and is matched as normal."""

PROVISIONAL_RULE = "SUSPECT.DEPENDENCY.PROVISIONAL.001"
"""This exact version is HELD FOR REVIEW by Cordon's feed: one signal flagged it minutes ago, and a
second signal or a person has not yet confirmed or cleared it (`FeedStore.read_provisional`).
Suspicious, not malicious -- nothing has confirmed it -- and HIGH, so the default gate pauses it."""

VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"

BUNDLED_RULE = "VULNERABLE.DEPENDENCY.BUNDLED.001"
"""An advisory about a dependency installing the target does not install (`Dependency.installed`):
one only a nested or vendored file in a published package records. Info: it never gates and never
feeds the verdict, but a bundled UI's vulnerable library may well be served, so it is shown."""

BUNDLED_MALWARE_RULE = "MALWARE.DEPENDENCY.BUNDLED.001"
"""A known-malicious release recorded by a file outside the install set. Its code may still ship in
the archive, so it is reported at high, not info."""

EXPLOITED_RULE = "VULNERABLE.DEPENDENCY.EXPLOITED.001"
"""A known vulnerability whose CVE is on CISA's KEV catalogue or ENISA's EUVD exploited list.
Its own rule so a policy can fail on "exploited" alone, and a CRA report can count it."""

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class AdvisoryFinding:
    """Building the advisory detector's findings."""

    #: The id every advisory finding carries, wherever in the package it is built.
    DETECTOR: ClassVar[str] = "advisory"

    @classmethod
    def removed_finding(
        cls, dependency: Dependency, spec: str, advisory: Advisory, ctx: ScanContext
    ) -> Finding:
        """The name is malicious in every version and gone from its registry (`REMOVED_RULE`)."""
        checked = RemovedNames.checked(dependency.ecosystem)
        return Finding(
            rule_id=REMOVED_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            message=(
                f"{dependency.name} is declared as {spec!r}. Every version of it is recorded as "
                f"malicious ({advisory.summary.strip()}), and its registry served nothing for it "
                f"when last checked{f' ({checked})' if checked else ''}, so an install fails "
                f"rather than installing the malware. Whoever registers {dependency.name} again "
                f"would have their code installed by this project."
            ),
            remediation=(
                f"Remove {dependency.name}, or replace it with the package it was meant to be; "
                f"a removed malicious name is usually a squat of a real one."
            ),
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{REMOVED_RULE}:{dependency.purl}".encode()),
                redaction=RedactionMode.NONE,
            ),
            explanation=Explanation(
                summary=f"{dependency.name} is a removed malicious name",
                matched_rule=REMOVED_RULE,
            ),
            risk=ctx.scorer.score(Severity.MEDIUM, Confidence.HIGH),
            detector=cls.DETECTOR,
            references=(references.OSV,),
        )

    @classmethod
    def _placeholder_finding(
        cls, dependency: Dependency, advisory: Advisory, ctx: ScanContext
    ) -> Finding:
        """The name was taken over, and this is what npm left in its place.

        Worth reporting and not worth the malicious claim: the dependency does
        nothing, the incident is real, and somebody should decide whether a
        package that no longer exists still belongs in the manifest. See
        `SECURITY_PLACEHOLDER`.
        """
        return Finding(
            rule_id=PLACEHOLDER_RULE,
            category=Category.POLICY,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            message=(
                f"{dependency.name} is pinned to npm's security placeholder, "
                f"{dependency.version}. The name was used to publish malware and "
                f"npm's security team took it over, replacing the releases with an "
                f"empty package. {advisory.summary} Nothing malicious installs from "
                f"this version -- it is what remediation left behind -- and the "
                f"dependency now does nothing at all, so whatever used to need it "
                f"is either unused or broken."
            ),
            remediation=(
                f"Remove {dependency.name} from the manifest, or replace it with the "
                f"package that actually provides what it was there for. The "
                f"placeholder is safe to install and it is not a dependency."
            ),
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(f"{PLACEHOLDER_RULE}:{dependency.purl}".encode()),
                redaction=RedactionMode.NONE,
            ),
            explanation=Explanation(
                summary=f"{dependency.name} is a withdrawn npm name",
                matched_rule=PLACEHOLDER_RULE,
            ),
            risk=ctx.scorer.score(Severity.MEDIUM, Confidence.CONFIRMED),
            detector=cls.DETECTOR,
            references=(references.OSV,),
        )

    @classmethod
    def finding(
        cls,
        dependency: Dependency,
        advisory: Advisory,
        ctx: ScanContext,
        *,
        advice: Callable[[Dependency], str],
    ) -> Finding:
        placeholder = (
            advisory.malicious
            and dependency.ecosystem == "npm"
            and bool(SECURITY_PLACEHOLDER.match(dependency.version or ""))
        )
        if placeholder:
            return cls._placeholder_finding(dependency, advisory, ctx)

        malicious = advisory.malicious
        rule_id = MALICIOUS_RULE if malicious else VULNERABLE_RULE
        confidence = Confidence.HIGH if advisory.is_range else Confidence.CONFIRMED
        if advisory.matched_through == "upstream":
            # The record names the package's upstream, which its ecosystem names exactly: one
            # step from the package, and a build may carry a patch the upstream did not.
            confidence = Confidence.HIGH
        elif advisory.matched_through == "nvd":
            # NVD's record for the CPE product a curated mapping names, by NVD's own range.
            confidence = Confidence.HIGH
        elif advisory.matched_through in ("inferred", "nvd-inferred"):
            # Through a tag found in the repository, spelled as the version, or through the CPE
            # product the guarded rule ties it to: still at the default gate, and set apart from
            # what was named exactly.
            confidence = Confidence.MEDIUM
        if malicious:
            severity = Severity.CRITICAL
        else:
            severity = _SEVERITY_MAP.get(advisory.severity.lower(), Severity.HIGH)
        exploitation = (
            None
            if malicious
            else exploited.ExploitedCatalogue.catalogue().lookup(
                exploited.ExploitedCatalogue.cves_of(advisory)
            )
        )
        if exploitation is not None:
            rule_id = EXPLOITED_RULE
            severity = Severity.CRITICAL
        bundled_in_extension, go_minimum, in_test_fixture, maintainers_only, severity = (
            AdvisoryFinding._conditions(ctx, dependency, exploitation, malicious, severity)
        )

        message, remediation = AdvisoryFinding._message_and_remediation(
            advice,
            advisory,
            bundled_in_extension,
            dependency,
            exploitation,
            go_minimum,
            maintainers_only,
            malicious,
        )

        return cls._scored(
            advisory,
            confidence,
            ctx,
            dependency,
            exploitation,
            in_test_fixture,
            malicious,
            message,
            remediation,
            rule_id,
            severity,
        )

    @staticmethod
    def _conditions(
        ctx: ScanContext,
        dependency: Dependency,
        exploitation: exploited.Exploitation | None,
        malicious: bool,
        severity: Severity,
    ) -> tuple[bool, bool, bool, bool, Severity]:
        """What about this match changes its grade: fixed only for maintainers, a Go minimum version, bundled inside an editor extension, or a malicious name sitting in test fixtures."""
        # In a published package, a lockfile is its maintainers' development environment: what
        # installing the package brings in comes from its declared metadata instead. Reported, at
        # LOW, so it informs without blocking the package. A malicious release is never lowered.
        maintainers_only = (
            not malicious and ctx.package_distribution and dependency.scope is not Scope.RUNTIME
        )
        if maintainers_only:
            severity = min(severity, Severity.LOW)
        # A published Go module's own `go.mod` `require` is a MINIMUM version: minimal version
        # selection may pick a newer one for the build that uses the module, and that build's own
        # go.mod and go.sum name what was selected -- and scanning that build reports the version
        # it really uses at full severity, exploited or not. Here it is reported at MEDIUM, saying
        # so, with an exploited one still named as exploited. Blocking on these blocked 75% of
        # 7,000 real modules, and keeping exploited ones blocking still blocked 26% (old
        # `golang.org/x/net` floors below the HTTP/2 rapid-reset fix) (review 98).
        go_minimum = (
            not malicious and ctx.distribution == "gomod" and dependency.scope is Scope.RUNTIME
        )
        if go_minimum:
            severity = min(severity, Severity.MEDIUM)
        # Bundled inside an editor extension: only the extension's author can upgrade it, and
        # blocking would leave whoever installs it a choice between the extension and the gate --
        # 451 of 1,943 popular extensions. Reported at MEDIUM, in every report and in the editor.
        # Not lowered when exploited in the wild, and a malicious release is never lowered.
        bundled_in_extension = (
            not malicious
            and exploitation is None
            and SourcePaths.is_editor_extension(dependency.declared_in or "")
        )
        if bundled_in_extension:
            severity = min(severity, Severity.MEDIUM)
        # A malicious release pinned by a test's own fixture lockfile -- pnpm's audit tests ship a
        # `has-vulnerabilities` fixture, Yarn's a `package-not-in-registry` one -- describes the
        # test, and nothing installs it. Reported, below the gate. Only test directories by their
        # whole name: an `examples/` lockfile is one somebody runs `npm install` in.
        in_test_fixture = malicious and any(
            segment.lower() in TEST_FIXTURE_SEGMENTS
            for segment in (dependency.declared_in or "").rpartition("!")[2].split("/")[:-1]
        )
        if in_test_fixture:
            severity = Severity.MEDIUM
        return bundled_in_extension, go_minimum, in_test_fixture, maintainers_only, severity

    @staticmethod
    def _message_and_remediation(
        advice: Callable[[Dependency], str],
        advisory: Advisory,
        bundled_in_extension: bool,
        dependency: Dependency,
        exploitation: exploited.Exploitation | None,
        go_minimum: bool,
        maintainers_only: bool,
        malicious: bool,
    ) -> tuple[str, str]:
        """What the finding says and what to do: a malicious release's message and removal, or a vulnerability's advisories, likelihood of exploitation and upgrade advice, with each condition that changes the advice."""
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
            # The CVE beside a GHSA or GO identifier: it is what a reader searches for, and what a
            # VEX statement or a ticket elsewhere will already be filed under.
            also = list(dict.fromkeys(a for a in advisory.aliases if a != advisory.identifier))
            named = (advisory.identifier or "an advisory") + (
                f" ({', '.join(also)})" if also else ""
            )
            message = (
                f"{dependency.name} {dependency.version} is named by {named}. {advisory.summary}"
            )
            # How likely exploitation is, beside whether it is known: FIRST's EPSS, offline.
            likelihood = exploited.Epss.lookup(exploited.ExploitedCatalogue.cves_of(advisory))
            if likelihood is not None:
                message = f"{message.rstrip()} {likelihood.describe()}"
            remediation = advice(dependency)
            if dependency.forced_by:
                # A pin written to satisfy one advisory, left behind by the next.
                message += (
                    f" This version is held in place by the override {dependency.forced_by}: "
                    f"upgrading the packages that depend on it will not move it."
                )
                remediation = f"Change the override {dependency.forced_by}. " + remediation
            if exploitation is not None:
                message += " " + exploitation.describe()
                remediation += (
                    " This one is exploited in the wild: fix it ahead of other advisories. Under "
                    "the EU Cyber Resilience Act an actively exploited vulnerability in a product "
                    "you ship is reportable within 24 hours of becoming aware of it."
                )
            if maintainers_only:
                message += (
                    f" It is pinned in {dependency.declared_in or 'a lockfile'} inside this package, which "
                    f"describes the maintainers' development environment; installing the package does "
                    f"not install it, so it is reported at LOW."
                )
            if go_minimum:
                message += (
                    " This module's go.mod asks for at least this version; a build that uses the "
                    "module may select a newer one, and that build's own go.mod names what it "
                    "selected. Reported at MEDIUM."
                )
            if bundled_in_extension:
                message += (
                    " It is bundled inside an editor extension, where only the extension's author "
                    "can upgrade it: reported at MEDIUM rather than blocking. Raise it with "
                    "--fail-on medium or the organisation's policy to block such extensions."
                )
        return message, remediation

    @classmethod
    def _scored(
        cls,
        advisory: Advisory,
        confidence: Confidence,
        ctx: ScanContext,
        dependency: Dependency,
        exploitation: exploited.Exploitation | None,
        in_test_fixture: bool,
        malicious: bool,
        message: str,
        remediation: str,
        rule_id: str,
        severity: Severity,
    ) -> Finding:
        """The finding, scored: the confidence a version range gives, the test-fixture ceiling, the evidence and the risk."""
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

        if in_test_fixture:
            message += (
                f" It is pinned in {dependency.declared_in}, a test's own fixture, which nothing "
                "installs; reported below the gate."
            )
        return Finding(
            rule_id=rule_id,
            category=(
                Category.SUSPICIOUS
                if in_test_fixture
                else Category.MALICIOUS
                if malicious
                else Category.VULNERABLE
            ),
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
                metadata=(("vulnerable_symbols", ",".join(advisory.symbols)),)
                if advisory.symbols
                else (),
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=match_summary,
                matched_rule=rule_id,
            ),
            risk=ctx.scorer.score(severity, confidence),
            detector=cls.DETECTOR,
            references=((advisory.reference,) if advisory.reference else ())
            + (exploitation.references() if exploitation is not None else ()),
            capabilities=(),
        )


__all__ = [
    "EXPLOITED_RULE",
    "MALICIOUS_RULE",
    "PLACEHOLDER_RULE",
    "PROVISIONAL_RULE",
    "REMOVED_RULE",
    "SECURITY_PLACEHOLDER",
    "TEST_FIXTURE_SEGMENTS",
    "VULNERABLE_RULE",
    "AdvisoryFinding",
]
