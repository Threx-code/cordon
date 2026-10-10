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

import re
from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.core import references
from cordon_scanner.core.inventory import OS_ECOSYSTEMS, RUNTIME_ECOSYSTEM
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
    Scope,
    Severity,
)
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import SourcePaths
from cordon_scanner.intel import exploited
from cordon_scanner.intel.advisories import Advisory, AdvisoryDatabase, AdvisoryFiles
from cordon_scanner.intel.ranges import VersionRanges
from cordon_scanner.intel.real import RealPackages

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import ScanContext, Unit

TEST_FIXTURE_SEGMENTS = frozenset(
    {"test", "tests", "testing", "fixture", "fixtures", "testdata", "__tests__", "spec"}
)
"""Directories that hold a test's own material, by their whole name."""

MALICIOUS_RULE = "MALWARE.DEPENDENCY.KNOWN.001"
PLACEHOLDER_RULE = "POLICY.DEPENDENCY.SECURITY_PLACEHOLDER.001"

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
VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"
EXPLOITED_RULE = "VULNERABLE.DEPENDENCY.EXPLOITED.001"
"""A known vulnerability whose CVE is on CISA's KEV catalogue or ENISA's EUVD exploited list.
Its own rule so a policy can fail on "exploited" alone, and a CRA report can count it."""
DATABASE_AGE_RULE = "OPERATIONAL.ADVISORY.DATABASE_AGE"
DATABASE_SCOPE_RULE = "OPERATIONAL.ADVISORY.DATABASE_SCOPE"
TAMPERED_RULE = "OPERATIONAL.ADVISORY.TAMPERED"
NO_FEED_RULE = "OPERATIONAL.ADVISORY.NO_FEED.001"

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
        self._advice: dict[tuple[str | None, str, str | None], str] = {}

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
                message=(
                    "A version in this project's dependency graph is named by an advisory as "
                    "malicious rather than merely vulnerable. The distinction is what the "
                    "advisory asserts: not that the code has a flaw, but that it was published "
                    "to do harm. Installing it ran whatever it carried, as the installing user."
                ),
                references=(references.OSV,),
                remediation=(
                    "Remove the version and treat every machine that installed it as compromised."
                ),
            ),
            DeclaredRule(
                id=PLACEHOLDER_RULE,
                title="Dependency pins npm's security placeholder",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                detector=AdvisoryDetector.id,
                message=(
                    "The package name was used to publish malware and npm's security "
                    "team took it over, replacing every release with an empty package "
                    "at a `-security` version. Pinning that placeholder is what "
                    "remediation leaves behind: nothing malicious installs, and the "
                    "dependency does nothing at all."
                ),
                remediation=(
                    "Remove the dependency, or replace it with the package that "
                    "provides what it was there for."
                ),
                references=(references.OSV,),
            ),
            DeclaredRule(
                id=VULNERABLE_RULE,
                title="Dependency has a known vulnerability",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=Category.VULNERABLE,
                detector=AdvisoryDetector.id,
                message=(
                    "A version in the dependency graph is named by a published advisory. The "
                    "match is on the resolved version rather than the declared range, so it "
                    "describes what would actually install."
                ),
                references=(references.OSV,),
                remediation="Upgrade to a version the advisory does not name.",
            ),
            DeclaredRule(
                id=EXPLOITED_RULE,
                title="Dependency has a vulnerability that is exploited in the wild",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.VULNERABLE,
                detector=AdvisoryDetector.id,
                message=(
                    "A version in the dependency graph is named by an advisory whose CVE is on "
                    "CISA's Known Exploited Vulnerabilities catalogue or ENISA's EUVD exploited "
                    "list: attackers are using it, not merely able to."
                ),
                references=(references.OSV, exploited.KEV_PAGE, exploited.EUVD_PAGE),
                remediation=(
                    "Upgrade now, ahead of other advisories. Under the EU Cyber Resilience Act an "
                    "actively exploited vulnerability in a product you ship is reportable within "
                    "24 hours of becoming aware of it."
                ),
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
        # Per inspection: the database a long-running server holds can be replaced between scans.
        self._advice = {}

        findings: list[Finding] = []

        if self._database.is_empty:
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
        refused = AdvisoryFiles.tampered_files()
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

        synced = AdvisoryFiles.refused_synced_files()
        if synced:
            findings.append(
                self.operational(
                    path=".",
                    message=(
                        f"{len(synced)} file(s) in the synced intel directory were not written by "
                        f"this install and were ignored: {', '.join(synced)}. The shipped database "
                        f"was used instead. Something else wrote to the cache directory."
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

        no_feed = self._no_feed_note(unit)
        if no_feed is not None:
            findings.append(no_feed)

        for dependency in unit.dependencies:
            if dependency.local:
                # A workspace member or a linked path: its code is in the repository and is
                # scanned as source. An advisory about a registry package that shares its name
                # describes someone else's bytes -- React's `eslint-plugin-react-internal@link:`
                # is not the npm package squatted under that name.
                continue
            reported: set[str] = set()
            for advisory in self._database.matching(
                dependency.ecosystem, dependency.name, dependency.version
            ):
                # One record can match through its version list and its range both.
                if advisory.identifier and advisory.identifier in reported:
                    continue
                reported.add(advisory.identifier)
                findings.append(self._finding(dependency, advisory, ctx))
            repository = self._repository_matches(dependency)
            if repository and not any(
                f.rule_id == MALICIOUS_RULE and f.location.package == dependency.purl
                for f in findings
            ):
                # One repository, one finding, however many records (its GIT record and its Go
                # module record name the same code).
                key, records = repository
                ids = ", ".join(sorted({a.identifier for a in records if a.identifier}))
                finding = self._finding(dependency, records[0], ctx)
                findings.append(
                    replace(
                        finding,
                        message=(
                            f"{dependency.name} is fetched from {key}, a repository recorded as "
                            f"malicious ({ids}): every commit of it, not one release. "
                            f"{records[0].summary}"
                        ).strip(),
                    )
                )
            if dependency.version is None and dependency.declared_spec:
                findings.extend(self._admitted_malware(dependency, ctx))
        return findings

    def _repository_matches(self, dependency: Dependency) -> tuple[str, list[Advisory]] | None:
        """Malicious-repository records for code this dependency fetches straight from a repository.

        A git dependency (`git+https://...`, `github:owner/repo`, a cargo `git =`), an action
        (`owner/repo`, which GitHub fetches from github.com) and a Go module (whose path is its
        repository) all run that repository's code whatever registry name, if any, they carry. A
        repository recorded as malicious -- in OSV's GIT records or as a Go module -- is matched
        here by `host/owner/repo`, every commit of it.
        """
        from cordon_scanner.intel.osv_import import OsvImport

        candidates: list[str] = []
        if dependency.ecosystem == "actions":
            candidates.append(f"github.com/{dependency.name}")
        elif dependency.ecosystem == "gomod":
            candidates.append(dependency.name)
        for text in (dependency.resolved_from, dependency.declared_spec):
            if text and (
                text.startswith(
                    ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh://")
                )
                or (text.startswith(("https://", "http://")) and ".git" in text)
                or text.startswith(
                    ("https://github.com/", "https://gitlab.com/", "https://bitbucket.org/")
                )
            ):
                candidates.append(text)
        for candidate in candidates:
            key = OsvImport.repository_key(candidate)
            if key is None:
                continue
            found: list[Advisory] = []
            for ecosystem in ("git", "gomod"):
                if ecosystem == dependency.ecosystem:
                    continue  # already matched by name above
                found.extend(
                    a
                    for a in self._database.for_package(ecosystem, key)
                    if a.malicious
                    and a.is_range
                    and a.affects("0.0.0")
                    and not (a.fixed or a.last_affected)
                )
            if found:
                return key, found
        return None

    def _admitted_malware(self, dependency: Dependency, ctx: ScanContext) -> Iterator[Finding]:
        """A declared range that admits a recorded malicious release.

        Without a lockfile, an install resolves each range to the highest release it admits on
        the day. `"easy-day-js": "^1.11.21"` admits the malicious `1.11.22`, and was how dozens of
        `@mastra/*` releases carried a payload while their own code stayed clean: nothing in the
        package was malicious except the range.
        """
        spec = dependency.declared_spec or ""
        if (
            re.match(r"(?:npm|file|link|workspace|portal|git\+?|https?|github):", spec.strip())
            or "/" in spec
        ):
            # Not a range over this name's registry releases: an alias, a path, a repository.
            return
        records = self._database.for_package(dependency.ecosystem, dependency.name)
        if dependency.name in RealPackages.real_packages(dependency.ecosystem) or any(
            not record.malicious for record in records
        ):
            # An established package with one compromised release -- chalk 5.6.1, debug 4.4.2,
            # @tanstack/react-router 1.169.5 -- had that release pulled from the registry within
            # hours, so a range over it no longer installs it, and every project declaring
            # `"chalk": "^5.0.0"` would be reported for nothing. Ordinary vulnerability records
            # are the evidence of a real codebase where the popularity list runs out; a lockfile
            # that pins the bad release is still reported, exactly.
            return
        if dependency.declared_in and SourcePaths.is_test_material(dependency.declared_in):
            # A fixture's manifest is test data nobody installs; react-native's
            # `__fixtures__/.../package.json` names `third-party-dep-a`, a name squatted since.
            return
        for advisory in records:
            if not advisory.malicious:
                continue
            if advisory.versions:
                admitted = [
                    v
                    for v in advisory.versions
                    if VersionRanges.admits(dependency.ecosystem, spec, v)
                ]
            elif advisory.affects("0") and not (advisory.fixed or advisory.last_affected):
                admitted = ["every version"]
            else:
                admitted = []
            if not admitted:
                continue
            release = admitted[-1] if admitted[-1] != "every version" else None
            finding = self._finding(replace(dependency, version=release or spec), advisory, ctx)
            where = (
                f"every version of {dependency.name} is recorded as malicious"
                if release is None
                else f"the declared range {spec!r} admits {release}, a recorded malicious release"
            )
            yield replace(
                finding,
                confidence=Confidence.HIGH,
                message=(
                    f"{dependency.name} is declared as {spec!r}, and {where}. An install that "
                    f"resolves without a lockfile can pull it. {advisory.summary}"
                ),
            )
            break

    def _no_feed_note(self, unit: GraphUnit) -> Finding | None:
        """Name the scanned ecosystems no advisory source covers.

        Cordon reads seventeen ecosystems and the bundled database holds records
        for eleven of them. A Conan, Conda, Bazel or CocoaPods dependency is therefore
        parsed, graphed, typosquat-checked and reported on -- and can never
        produce a vulnerability finding, because there is nothing to match it
        against. Without this, that scan ended in "0 findings, scan complete",
        which is the shape of report this project treats as the worst failure
        available to a scanner: a check that never ran, indistinguishable from
        one that ran and found nothing.

        The database-scope note beside it lists the sources that *do* exist, and
        reading an absence out of a list of twelve is not disclosure.
        """
        # An image's OS packages have a source -- OSV, matched by the `os-packages` detector under
        # --online -- and the engine says when they went unmatched. "No source covers deb" would
        # be untrue.
        scanned = {
            d.ecosystem
            for d in unit.dependencies
            if d.ecosystem and d.ecosystem not in OS_ECOSYSTEMS
        }
        # An image reference has no advisories of its own: its vulnerabilities are its packages',
        # matched when the image itself is scanned. Unless a feed names images, it is not a check
        # that did not run.
        # A runtime's own release (node, python) has no advisory source; the engine's inventory
        # says so per package, and Go's is matched as `stdlib`.
        uncovered = sorted(
            e
            for e in scanned
            if not self._database.covers(e) and e not in ("image", RUNTIME_ECOSYSTEM)
        )
        if not uncovered:
            return None
        counted = sum(1 for d in unit.dependencies if d.ecosystem in uncovered)
        return self.operational(
            path=".",
            message=(
                f"No advisory source covers {', '.join(uncovered)}, so {counted} "
                f"dependency(ies) were not checked for known vulnerabilities or "
                f"known-malicious releases. They were not checked and found clean; "
                f"they were not checked. Everything else about them -- typosquats, "
                f"install hooks, lockfile integrity, licences -- was examined."
            ),
            detail="advisories",
            rule_id=NO_FEED_RULE,
            degrades_coverage=True,
        )

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

    def _upgrade_advice(self, dependency: Dependency) -> str:
        """`_advise`, once per package version in an inspection, however many advisories name it."""
        key = (dependency.ecosystem, dependency.name, dependency.version)
        cached = self._advice.get(key)
        if cached is None:
            cached = self._advise(dependency)
            self._advice[key] = cached
        return cached

    def _advise(self, dependency: Dependency) -> str:
        """Where to move to, rather than where not to stay.

        "Upgrade to a version the advisory does not name" is true and useless:
        it leaves the reader to collect every advisory for the package, order
        the versions by that ecosystem's rules, and check each candidate against
        the others -- because the version that fixes one advisory is routinely
        named by the next.

        Two kinds of record support two different answers, and the difference is
        stated rather than smoothed over. A range record names the version the
        fix landed in, so the lowest such version that nothing else names is an
        exact floor. An enumerated record lists affected releases and nothing
        else, so the most that can be said is which affected release is the
        highest -- anything at or below it is named by something.
        """
        from functools import cmp_to_key

        from cordon_scanner.intel.versions import Versions

        generic = "Upgrade to a version the advisory does not name."
        if not dependency.version or not dependency.ecosystem:
            return generic
        records = self._database.for_package(dependency.ecosystem, dependency.name)
        if not records:
            return generic

        ecosystem = dependency.ecosystem

        def _ordering(left: str, right: str) -> int:
            return Versions.compare(ecosystem, left, right)

        order = cmp_to_key(_ordering)

        fixed = sorted({r.fixed for r in records if r.fixed}, key=order)
        for candidate in fixed:
            if Versions.compare(ecosystem, candidate, dependency.version) <= 0:
                continue
            if not any(record.affects(candidate) for record in records):
                return (
                    f"Upgrade to {candidate} or later: the advisories record it as "
                    f"the first unaffected release of {dependency.name}. A `fixed` "
                    f"version is what the advisory claims, not what the registry "
                    f"has published -- if nothing at or above it exists yet, this "
                    f"package has no fixed release and the mitigation in the "
                    f"advisory is the only control."
                )

        affecting = [r for r in records if r.affects(dependency.version)]
        named = sorted({version for record in affecting for version in record.versions}, key=order)
        if named:
            return (
                f"Upgrade past {named[-1]}: the advisories that name "
                f"{dependency.version} also name every release up to that one. The "
                f"database lists affected versions rather than fixed ones for this "
                f"package, so the first safe release is not stated here."
            )
        return generic

    def _placeholder_finding(
        self, dependency: Dependency, advisory: Advisory, ctx: ScanContext
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
            detector=self.id,
            references=(references.OSV,),
        )

    def _finding(self, dependency: Dependency, advisory: Advisory, ctx: ScanContext) -> Finding:
        placeholder = (
            advisory.malicious
            and dependency.ecosystem == "npm"
            and bool(SECURITY_PLACEHOLDER.match(dependency.version or ""))
        )
        if placeholder:
            return self._placeholder_finding(dependency, advisory, ctx)

        malicious = advisory.malicious
        rule_id = MALICIOUS_RULE if malicious else VULNERABLE_RULE
        confidence = Confidence.HIGH if advisory.is_range else Confidence.CONFIRMED
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
        # In a published package, a lockfile is its maintainers' development environment: what
        # installing the package brings in comes from its declared metadata instead. Reported, at
        # LOW, so it informs without blocking the package. A malicious release is never lowered.
        maintainers_only = (
            not malicious and ctx.package_distribution and dependency.scope is not Scope.RUNTIME
        )
        if maintainers_only:
            severity = min(severity, Severity.LOW)
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
            remediation = self._upgrade_advice(dependency)
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
            detector=self.id,
            references=((advisory.reference,) if advisory.reference else ())
            + (exploitation.references() if exploitation is not None else ()),
            capabilities=(),
        )


__all__ = ["AdvisoryDetector"]
