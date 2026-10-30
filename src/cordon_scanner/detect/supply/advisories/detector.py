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
from typing import TYPE_CHECKING, Any

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, GraphUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.supply.advisories.findings import (
    MALICIOUS_RULE,
    PROVISIONAL_RULE,
    AdvisoryFinding,
)
from cordon_scanner.detect.supply.advisories.rule_declarations import DECLARED_RULES
from cordon_scanner.foundation import references
from cordon_scanner.foundation.dependencies import OS_ECOSYSTEMS, RUNTIME_ECOSYSTEM
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
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase, AdvisoryFiles
from cordon_scanner.intel.advisories.ranges import VersionRanges
from cordon_scanner.intel.advisories.upstream_advisories import SUPPORTED as UPSTREAM_ECOSYSTEMS
from cordon_scanner.intel.advisories.upstream_advisories import UpstreamAdvisories, UpstreamResult
from cordon_scanner.intel.registry import BuiltinPackageNames

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import ScanContext, Unit


DATABASE_AGE_RULE = "OPERATIONAL.ADVISORY.DATABASE_AGE"
DATABASE_SCOPE_RULE = "OPERATIONAL.ADVISORY.DATABASE_SCOPE"
TAMPERED_RULE = "OPERATIONAL.ADVISORY.TAMPERED"
NO_FEED_RULE = "OPERATIONAL.ADVISORY.NO_FEED.001"

#: The feed files some ecosystems share (`advisories._SHARED_DATA`): gradle reads maven's.
_SHARED_DATA_KEYS = {"gradle": "maven"}


STALE_AFTER_DAYS = 45
"""How old the bundled snapshot can get before the coverage note escalates
from an FYI to something worth acting on. Between Trivy's 24-hour default (a
DB it refreshes on every run) and a PyPI release cadence measured in weeks --
this project's own data is refreshed weekly by `refresh-advisories.yml` but
only *shipped* at release time, so a few weeks old is normal, not stale."""


class AdvisoryDetector(BaseDetector):
    """Reports dependencies that are known to be malicious or vulnerable."""

    id = AdvisoryFinding.DETECTOR
    version = "0.1.0"
    categories = frozenset({Category.MALICIOUS, Category.VULNERABLE, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=False, dependencies=True)

    def __init__(self, database: AdvisoryDatabase | None = None) -> None:
        # `is None`, not `or`. An AdvisoryDatabase is falsy when empty, so
        # `database or bundled()` silently replaced a deliberately empty
        # database -- an organisation stating "these are the only advisories I
        # act on" got the shipped list instead, which is the substitution this
        # project argues against everywhere else.
        self._database = AdvisoryDatabase.bundled() if database is None else database
        self._advice: dict[tuple[str | None, str, str | None], str] = {}
        #: The feed's provisional verdicts per ecosystem, read on first use (`_provisional`).
        self._provisional_cache: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return DECLARED_RULES

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

        self._database_notes(findings)

        # Ecosystems no advisory source covers, matched through the upstream their own data names
        # (`intel/upstream_advisories`), when the scan may use the network.
        upstream: UpstreamResult | None = None
        if not ctx.offline:
            candidates = [
                d
                for d in unit.dependencies
                if not d.local
                and not d.bundled
                and d.ecosystem in UPSTREAM_ECOSYSTEMS
                and not self._database.covers(d.ecosystem)
            ]
            if candidates:
                upstream = UpstreamAdvisories.check(candidates)
        # Then NVD (`intel/nvd`), for what no repository route named -- offline too, since its data
        # is bundled: tied to a CPE product by a curated mapping, or by the guarded rule from the
        # homepage and download the route read on the way.
        upstream = self._with_nvd(unit, upstream)
        no_feed = self._no_feed_note(
            unit, ctx.config.policy.accept_no_feed or frozenset(), upstream
        )
        if no_feed is not None:
            findings.append(no_feed)

        self._dependency_findings(ctx, findings, unit, upstream)
        return findings

    def _database_notes(self, findings: list[Finding]) -> None:
        """What the scan says about the advisory data itself: files that failed their integrity check, synced files refused, data that has gone stale, and what it does not contain."""
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

    def _dependency_findings(
        self,
        ctx: ScanContext,
        findings: list[Finding],
        unit: GraphUnit,
        upstream: UpstreamResult | None,
    ) -> None:
        """Each dependency's findings: its advisories, a provisional hold the feed keeps on it, malicious repositories its code is fetched from, and a declared range that admits a recorded malicious release."""
        for dependency in unit.dependencies:
            if dependency.local:
                # A workspace member or a linked path: its code is in the repository and is
                # scanned as source. An advisory about a registry package that shares its name
                # describes someone else's bytes -- React's `eslint-plugin-react-internal@link:`
                # is not the npm package squatted under that name.
                continue
            reported: set[str] = set()
            for advisory in (
                *self._own_records(dependency),
                *(upstream.advisories.get(dependency.purl, ()) if upstream is not None else ()),
            ):
                # One record can match through its version list and its range both.
                if advisory.identifier and advisory.identifier in reported:
                    continue
                reported.add(advisory.identifier)
                findings.append(
                    AdvisoryFinding.finding(dependency, advisory, ctx, advice=self._upgrade_advice)
                )
            held = self._provisional_hold(dependency, findings, ctx)
            if held is not None:
                findings.append(held)
            repository = self._repository_matches(dependency)
            if repository and not any(
                f.rule_id == MALICIOUS_RULE and f.location.package == dependency.purl
                for f in findings
            ):
                # One repository, one finding, however many records (its GIT record and its Go
                # module record name the same code).
                key, records = repository
                ids = ", ".join(sorted({a.identifier for a in records if a.identifier}))
                finding = AdvisoryFinding.finding(
                    dependency, records[0], ctx, advice=self._upgrade_advice
                )
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

    def _own_records(self, dependency: Dependency) -> tuple[Advisory, ...]:
        """The records about this dependency by its own name: by version, and for an image pinned by
        digest by that digest too (an image record lists its digest among its versions). A Helm chart
        record that names its repositories holds only for a chart from one of them."""
        found = self._database.matching(dependency.ecosystem, dependency.name, dependency.version)
        pin = dependency.integrity or ""
        if (
            dependency.ecosystem == "image"
            and pin.startswith("sha256:")
            and pin != dependency.version
        ):
            found = (
                *found,
                *(
                    a
                    for a in self._database.matching("image", dependency.name, pin)
                    if a not in found
                ),
            )
        if dependency.ecosystem == "helm":
            source = AdvisoryDetector._repository_key(
                dependency.resolved_from or dependency.source[1] or ""
            )
            found = tuple(
                a
                for a in found
                if not a.repositories
                or (
                    source
                    and source in {AdvisoryDetector._repository_key(r) for r in a.repositories}
                )
            )
        return found

    @staticmethod
    def _repository_key(location: str) -> str:
        """A chart repository as written in any of its spellings, compared without scheme or slash."""
        text = location.strip().lower()
        for scheme in ("https://", "http://", "oci://"):
            text = text.removeprefix(scheme)
        return text.rstrip("/")

    def _repository_matches(self, dependency: Dependency) -> tuple[str, list[Advisory]] | None:
        """Malicious-repository records for code this dependency fetches straight from a repository.

        A git dependency (`git+https://...`, `github:owner/repo`, a cargo `git =`), an action
        (`owner/repo`, which GitHub fetches from github.com) and a Go module (whose path is its
        repository) all run that repository's code whatever registry name, if any, they carry. A
        repository recorded as malicious -- in OSV's GIT records or as a Go module -- is matched
        here by `host/owner/repo`, every commit of it.
        """
        from cordon_scanner.intel.advisories.osv_import import OsvImport

        candidates: list[str] = []
        if dependency.ecosystem == "actions":
            candidates.append(f"github.com/{dependency.name}")
        elif dependency.ecosystem == "gomod":
            candidates.append(dependency.name)
        for text in (dependency.resolved_from, dependency.declared_spec):
            if text and (
                text.startswith(
                    (
                        "git+",
                        "git:",
                        "git@",
                        "github:",
                        "gitlab:",
                        "bitbucket:",
                        "ssh://",
                        "https://github.com/",
                        "https://gitlab.com/",
                        "https://bitbucket.org/",
                    )
                )
                or (text.startswith(("https://", "http://")) and ".git" in text)
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
        if dependency.name in BuiltinPackageNames.established(dependency.ecosystem) or any(
            not record.malicious for record in records
        ):
            # An established package with one compromised release -- chalk 5.6.1, debug 4.4.2,
            # @tanstack/react-router 1.169.5 -- had that release pulled from the registry within
            # hours, so a range over it no longer installs it, and every project declaring
            # `"chalk": "^5.0.0"` would be reported for nothing. Ordinary vulnerability records
            # are the evidence of a real codebase where the popularity list runs out; a lockfile
            # that pins the bad release is still reported, exactly.
            return
        if dependency.declared_in and "node_modules/" in dependency.declared_in.replace("\\", "/"):
            # The manifest of a copy already installed: nothing resolves its ranges again, and its
            # devDependencies are installed by nobody. `keyv`'s own package.json declares
            # `"@keyv/test-suite": "*"` as a dev dependency, and 86 legitimate editor extensions
            # that bundle keyv were blocked for it. What is installed is read from the installed
            # copy's own version, which is still matched exactly.
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
            if release is None and dependency.name in BuiltinPackageNames.removed(
                dependency.ecosystem
            ):
                yield AdvisoryFinding.removed_finding(dependency, spec, advisory, ctx)
                break
            finding = AdvisoryFinding.finding(
                replace(dependency, version=release or spec),
                advisory,
                ctx,
                advice=self._upgrade_advice,
            )
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

    def _with_nvd(self, unit: GraphUnit, upstream: UpstreamResult | None) -> UpstreamResult | None:
        from cordon_scanner.intel.advisories.nvd import ECOSYSTEMS as NVD_ECOSYSTEMS
        from cordon_scanner.intel.advisories.nvd import NvdAdvisories

        candidates = [
            d
            for d in unit.dependencies
            if not d.local
            and not d.bundled
            and d.ecosystem in NVD_ECOSYSTEMS
            and not self._database.covers(d.ecosystem)
            and not (upstream is not None and d.purl in upstream.checked)
        ]
        if not candidates:
            return upstream
        found = NvdAdvisories.check(
            candidates,
            upstream.homes if upstream is not None else {},
            upstream.versions if upstream is not None else {},
        )
        merged = upstream if upstream is not None else UpstreamResult()
        merged.checked |= found.checked
        merged.advisories.update(found.advisories)
        for dependency in candidates:
            if dependency.purl in found.checked:
                merged.unchecked.pop(dependency.purl, None)
            elif dependency.purl in found.unchecked:
                before = merged.unchecked.get(dependency.purl)
                merged.unchecked[dependency.purl] = (
                    f"{before}; and NVD: {found.unchecked[dependency.purl]}"
                    if before
                    else f"NVD: {found.unchecked[dependency.purl]}"
                )
        return merged

    def _no_feed_note(
        self, unit: GraphUnit, accepted: frozenset[str], upstream: UpstreamResult | None
    ) -> Finding | None:
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
        # What was asked of OSV through its upstream (`intel/upstream_advisories`) was checked;
        # the rest is named, with why.
        unchecked = [
            d
            for d in unit.dependencies
            if d.ecosystem in uncovered
            and not d.local
            and not d.bundled
            and not (upstream is not None and d.purl in upstream.checked)
        ]
        if not unchecked:
            return None
        ecosystems = sorted({str(d.ecosystem) for d in unchecked})
        derivable = [e for e in ecosystems if e in UPSTREAM_ECOSYSTEMS]
        why = AdvisoryDetector._why_unchecked(derivable, unchecked, upstream)
        # `policy.accept_no_feed`: still named here, every time, but no longer a scan that did
        # not finish -- unless an ecosystem the policy does not accept is among them.
        unaccepted = [e for e in ecosystems if e not in accepted]
        taken = [e for e in ecosystems if e in accepted]
        return self.operational(
            path=".",
            message=(
                f"{len(unchecked)} {', '.join(ecosystems)} dependency(ies) were not checked for "
                f"known vulnerabilities or known-malicious releases: no advisory source covers "
                f"them directly. They were not checked and found clean; they were not checked. "
                f"Everything else about them -- typosquats, install hooks, lockfile integrity, "
                f"licences -- was examined."
                + why
                + (
                    f" The policy accepts this for {', '.join(taken)} (policy.accept_no_feed)."
                    if taken
                    else ""
                )
            ),
            detail="advisories",
            rule_id=NO_FEED_RULE,
            degrades_coverage=bool(unaccepted),
        )

    @staticmethod
    def _why_unchecked(
        derivable: list[str], unchecked: list[Dependency], upstream: UpstreamResult | None
    ) -> str:
        """Why the uncovered dependencies went unchecked: what --online would add, or the reasons the upstream lookup gave."""
        if upstream is None:
            why = (
                f" With --online, {', '.join(derivable)} packages are matched through the upstream "
                f"repository their ecosystem names, asked of OSV."
                if derivable
                else ""
            )
        else:
            reasons: dict[str, list[str]] = {}
            for d in unchecked:
                reason = upstream.unchecked.get(d.purl)
                if reason:
                    reasons.setdefault(reason, []).append(f"{d.name}")
            why = "".join(
                f" {', '.join(names[:3])}{f' and {len(names) - 3} more' if len(names) > 3 else ''}: "
                f"{reason}."
                for reason, names in sorted(reasons.items(), key=lambda kv: -len(kv[1]))[:5]
            )
        return why

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

        from cordon_scanner.intel.advisories.versions import Versions

        generic = "Upgrade to a version the advisory does not name."
        if not dependency.version or not dependency.ecosystem:
            return generic
        records = self._database.for_package(dependency.ecosystem, dependency.name)
        if not records:
            return generic

        ecosystem = dependency.ecosystem

        def _ordering(left: str, right: str) -> int:
            return Versions.compare(ecosystem, left, right)

        compared = cmp_to_key(_ordering)

        def order(version: str) -> tuple[Any, str]:
            """The ecosystem's order, then the spelling: versions it calls equal ("1.3" and
            "1.3.0") otherwise kept a set's order, which follows the process's hash seed, so the
            version a remediation names changed from one run to the next."""
            return compared(version), version

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

    def _provisional_hold(
        self, dependency: Dependency, findings: list[Finding], ctx: ScanContext
    ) -> Finding | None:
        """A pause on this exact version, if Cordon's feed holds it for review and nothing has
        already condemned it. Matched by name and exact version only, never by name alone."""
        if dependency.version is None or any(
            f.rule_id == MALICIOUS_RULE and f.location.package == dependency.purl for f in findings
        ):
            return None
        record = next(
            (
                r
                for r in self._provisional(dependency.ecosystem)
                if str(r.get("name", "")).lower() == dependency.name.lower()
                and dependency.version in {str(v) for v in r.get("versions") or ()}
            ),
            None,
        )
        if record is None:
            return None
        identifier = str(record.get("id", ""))
        return Finding(
            rule_id=PROVISIONAL_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message=(
                f"{dependency.name} {dependency.version} is held for review by Cordon's feed "
                f"({identifier}): one signal flagged this exact version as malicious and it is paused "
                f"until a second signal or a person confirms or clears it. "
                f"{str(record.get('summary', ''))[:300]}"
            ).strip(),
            remediation=(
                f"Keep the previous version of {dependency.name} until the hold is decided; it lifts "
                f"by itself if the verdict is cleared."
            ),
            location=Location(
                path=dependency.declared_in or dependency.project or ".",
                package=dependency.purl,
                project=dependency.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.GRAPH,
                match_hash=Evidence.hash_bytes(
                    f"{PROVISIONAL_RULE}:{dependency.purl}:{identifier}".encode()
                ),
                redaction=RedactionMode.NONE,
            ),
            explanation=Explanation(
                summary=f"{dependency.name} {dependency.version} is held for review",
                matched_rule=PROVISIONAL_RULE,
            ),
            risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
            detector=AdvisoryFinding.DETECTOR,
            references=(references.OSV,),
        )

    def _provisional(self, ecosystem: str) -> list[dict[str, Any]]:
        """The feed's provisional verdicts for one ecosystem, read once per detector."""
        cache = self._provisional_cache
        if ecosystem not in cache:
            from cordon_scanner.intel.malware.feed import FeedStore

            try:
                cache[ecosystem] = FeedStore.read_provisional(
                    _SHARED_DATA_KEYS.get(ecosystem, ecosystem)
                )
            except (OSError, ValueError):
                cache[ecosystem] = []
        return cache[ecosystem]


__all__ = ["AdvisoryDetector"]
