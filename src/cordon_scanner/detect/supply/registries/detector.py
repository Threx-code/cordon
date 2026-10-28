"""Questions about dependencies that only a registry can answer.

Three facts have no local source, and each closes a gap the offline detectors
cannot reach:

**Withdrawal.** A version yanked from PyPI or unpublished from npm was
withdrawn by somebody -- often because it was malicious, often because it was
broken. A lockfile pins it happily either way, and nothing in the repository
records that the pin now points at something its own publisher retracted.

**Distance from what is published.** A pin far behind the current release is
ordinary in a conservative project and is also what a downgrade attack produces.
This reports the distance and says nothing about the cause, because the
difference between the two is a decision the reader makes with context this tool
does not have.

**Integrity.** A lockfile records a hash. The registry records a hash. If they
disagree, one of them is not describing the artefact that will be installed, and
that is worth interrupting a build over.

Every finding from here is marked as depending on a network answer, because it
does: rerun the same scan offline and it disappears, rerun it next week and it
may differ. That is a property of the question, not a defect, and a report that
did not say so would be claiming a reproducibility it does not have.

The detector requires `network`, so the engine skips it entirely unless the scan
was explicitly taken online. Failures are reported rather than swallowed -- an
unreachable registry means the questions went unanswered, which is not the same
as answering "no".

**The source a package claims.** A manifest names the repository the package is
built from, and that link is the thing most people actually check before
depending on something: they read the code on the forge and assume it is the
code in the artefact. Nothing enforces the connection. A package can point at a
well-regarded repository it has no relationship with, and the registry's own
record of that package is the only place the disagreement shows up.

So the comparison is between the repository this project's manifest declares and
the repository the registry records for the same package name. It runs on the
manifests in the scan target rather than on the dependency graph, because that
is where the local claim lives: a lockfile pins a name, a version and a hash,
and records nothing about where the code came from. Both sides are reduced to a
forge, an owner and a repository name before comparing, so a shorthand, an SSH
URL and a link into a monorepo subdirectory all compare equal to the plain HTTPS
form -- what differs after that is a real disagreement rather than a spelling.

A package the registry has never heard of produces nothing. Most manifests in
most repositories are for something unpublished, and treating "not found" as a
mismatch would report every private project in existence.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING

from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.dependencies import NAMED_BY_FILE, OS_ECOSYSTEMS, RUNTIME_ECOSYSTEM
from cordon_scanner.foundation.models import (
    Category,
    Finding,
    Scope,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.results import Dependency
    from cordon_scanner.intel.registries.private_registries import PrivateRegistry
    from cordon_scanner.intel.registries.registry_client import PackageFacts
from cordon_scanner.detect.supply.registries.evidence import RegistryEvidence
from cordon_scanner.detect.supply.registries.findings import RegistryFinding
from cordon_scanner.detect.supply.registries.notices import RegistryNotices
from cordon_scanner.detect.supply.registries.rule_declarations import DECLARED_RULES, DETECTOR

MAX_QUERIES = 200
"""How many packages one scan will ask about.

A large graph would otherwise mean thousands of requests, which is slow enough
that people stop passing the flag, and impolite enough to the registry that it
deserves a ceiling. Direct dependencies are asked about first, because those are
the ones somebody chose."""

MAX_MANIFEST_QUERIES = 50
"""How many manifests one scan will ask the registry about.

A monorepo has hundreds, and asking about every one of them turns a scan into a
few hundred sequential requests -- slow enough that people stop passing
`--online`, and impolite enough to the registry that it deserves a ceiling.
The first fifty are the ones nearest the top of the walk, which in a monorepo
are the ones somebody publishes."""

REGISTRY_ECOSYSTEMS = frozenset(
    {
        "npm",
        "pypi",
        "cargo",
        "rubygems",
        "nuget",
        "gomod",
        "maven",
        "gradle",
        "composer",
        "pub",
        "hex",
        "cocoapods",
        "conda",
        "cran",
        "hackage",
        "julia",
        "opam",
        "conan",
        "vcpkg",
        "actions",
        "ansible",
        "terraform",
        "helm",
        "bazel",
        "homebrew",
        "image",
    }
)
"""Ecosystems whose registry this can ask. Kept beside the client's own host
map so a manifest for an ecosystem with no configured registry is skipped
before a request is built rather than after it fails."""

CONFUSABLE_ECOSYSTEMS = frozenset({"npm", "pypi", "cargo", "rubygems", "nuget", "pub", "hex"})
"""Where a name missing from the public registry is a dependency-confusion risk.

Not Composer either: since Composer 2 a custom repository is canonical for every package it
holds, so Packagist is never consulted for a name a private repository serves.

Not Go and not Maven. A Go module path is a URL its owner controls and Maven Central verifies
group ownership by domain, so a private module or artefact absent from the public index cannot
be shadowed by a stranger registering the name - and both are absent for every private module
in existence, so reporting them would bury the finding where it means something."""

MIN_ATTESTED_SIBLINGS = 3
"""How many *earlier* attested releases make an unattested one worth reporting.

One is a project that tried provenance once. A handful is a project that
publishes with it, and a release that skipped it did not come from the pipeline
the others came from.

Earlier ones only, which the client counts. A package that adopted provenance
last month has an attested latest and an unattested everything-else, and
counting totals would put this finding on every pin that predates the practice
-- `requests==2.31.0` among them, which skipped nothing."""


class RegistryDetector(BaseDetector):
    """Enriches the dependency graph with what the registry says."""

    id = DETECTOR
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, dependencies=True, network=True)

    def __init__(self) -> None:
        self._manifests_asked = 0

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies) and not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return DECLARED_RULES

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.offline:
            return ()
        if isinstance(unit, FileUnit):
            return self._manifest_findings(unit, ctx)
        if not isinstance(unit, GraphUnit):
            return ()

        findings: list[Finding] = []
        unanswered: list[str] = []

        # Only the ecosystems this can actually ask. `facts()` raises for the
        # rest, which landed them in `unanswered` beside genuine network
        # failures -- so a Cargo lockfile scanned with --online reported that
        # its packages "could not be checked against their registry", which
        # reads as a transient outage rather than a capability this tool does
        # not have.
        # A container image's OS packages come from the distribution's own signed repositories,
        # not a language registry; they are matched against distribution advisories instead.
        unsupported = sorted(
            {
                d.ecosystem
                for d in unit.dependencies
                if d.ecosystem not in REGISTRY_ECOSYSTEMS
                and d.ecosystem not in OS_ECOSYSTEMS
                and d.ecosystem != RUNTIME_ECOSYSTEM
            }
        )
        from cordon_scanner.intel.registries.private_registries import (
            PrivateRegistry,
        )

        # Registries the organisation runs, with the credential the operator named for each.
        configured = tuple(PrivateRegistry(*pair) for pair in ctx.config.private_registries)
        askable, asking, private_images = self._worth_asking(configured, unit)
        # Counted, not inferred from the finding below. A reader reconciling
        # "250 dependencies" against "200 could not be checked" concludes that
        # fifty were checked and came back clean, and the fifty past the ceiling
        # were never asked about at all.
        over_ceiling = len(askable) - len(asking)
        ran_out_of_time = 0

        ran_out_of_time = self._ask(asking, configured, ctx, findings, ran_out_of_time, unanswered)

        RegistryDetector._coverage_notes(
            askable,
            ctx,
            findings,
            over_ceiling,
            private_images,
            ran_out_of_time,
            unanswered,
            unit,
            unsupported,
        )
        return findings

    def _worth_asking(
        self, configured: tuple[PrivateRegistry, ...], unit: GraphUnit
    ) -> tuple[list[Dependency], list[Dependency], list[Dependency]]:
        """Which dependencies to ask the registries about, in the order the question budget is spent: what a registry can answer, without a private image's internal names, up to the query ceiling."""
        from cordon_scanner.ecosystems.infra.image import (
            ImageEcosystem,
            ImageReference,
            PublicRegistries,
        )
        from cordon_scanner.intel.registries.private_registries import PrivateRegistries

        # An image pinned by digest alone is asked about by its digest. An image on a registry
        # an organisation runs answers only with credentials: asked with them where the operator
        # supplied some, and otherwise counted, not asked.
        private_images = [
            d
            for d in unit.dependencies
            if d.ecosystem == "image"
            and ImageEcosystem.is_reference(d.name, d.declared_spec)
            and (reference := ImageReference.parse(d.name)) is not None
            and not PublicRegistries.covers(reference.registry)
            and PrivateRegistries.matching(configured, "image", d.name, None) is None
        ]
        askable = [
            d
            for d in self._order(unit.dependencies)
            # The project's own code (a path pod, a workspace member, an example's `path: ../`) is
            # no registry's: asking leaks its name to the public one, and the answer was false --
            # `appmetrica` "not on the public pub registry", `FlutterMacOS` "withdrawn".
            if not d.local
            # Part of the platform -- a language's own library (R's `grid`, Julia's stdlibs), the
            # runtime or OS it targets -- or shipped inside another package: no registry's either.
            and d.scope is not Scope.PLATFORM
            and not d.bundled
            # A jar named only by its file has no real Maven coordinate to ask about: "absent from
            # Maven Central" would be true of a name Cordon made up, and read as dependency confusion.
            and d.resolved_from != NAMED_BY_FILE
            and (d.version or (d.ecosystem == "image" and d.integrity))
            and d.ecosystem in REGISTRY_ECOSYSTEMS
            and d not in private_images
            # A Dockerfile's `ADD` of a URL or repository is no registry's to answer for.
            and (d.ecosystem != "image" or ImageEcosystem.is_reference(d.name, d.declared_spec))
        ]
        asking = askable[:MAX_QUERIES]
        return askable, asking, private_images

    def _ask(
        self,
        asking: list[Dependency],
        configured: tuple[PrivateRegistry, ...],
        ctx: ScanContext,
        findings: list[Finding],
        ran_out_of_time: int,
        unanswered: list[str],
    ) -> int:
        """Ask the registries about each dependency in turn, within the time budget: what each answers is compared with what the project declares, a name no public registry knows is reported, and a question that went unanswered is kept for the coverage note. How many were left unasked when time ran out."""
        from cordon_scanner.intel.registries.private_registries import PrivateRegistries
        from cordon_scanner.intel.registries.registry_client import (
            PackageNotFound,
            RegistryClient,
            RegistryError,
        )

        for index, dependency in enumerate(asking):
            if ctx.out_of_time():
                ran_out_of_time = len(asking) - index
                break
            private = PrivateRegistries.matching(
                configured, dependency.ecosystem, dependency.name, dependency.resolved_from
            )
            try:
                observed = (
                    PrivateRegistries.facts(
                        private,
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version
                        or (dependency.integrity if dependency.ecosystem == "image" else None),
                    )
                    if private is not None
                    else RegistryClient.facts(
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version,
                        source=dependency.resolved_from,
                    )
                    if dependency.ecosystem == "helm" and dependency.resolved_from
                    else RegistryClient.facts(
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version or dependency.integrity,
                    )
                    if dependency.ecosystem == "image"
                    else RegistryClient.facts(
                        dependency.ecosystem, dependency.name, dependency.version
                    )
                )
            except PackageNotFound:
                if dependency.ecosystem in CONFUSABLE_ECOSYSTEMS and not self._resolved_privately(
                    dependency
                ):
                    findings.append(
                        RegistryFinding.finding(
                            "SUSPECT.DEPENDENCY.UNREGISTERED.001",
                            ctx,
                            dependency=dependency,
                            detail=(
                                f"{dependency.name} is not on the public {dependency.ecosystem} registry. "
                                f"Either it is private, and a public package registered under the name "
                                f"could be installed in its place, or the name was invented -- AI coding "
                                f"assistants suggest package names that do not exist, and attackers "
                                f"register them."
                            ),
                        )
                    )
                continue
            except RegistryError as exc:
                unanswered.append(f"{dependency.name}: {exc}")
                continue
            findings.extend(self._compare(dependency, observed, ctx))
        return ran_out_of_time

    @staticmethod
    def _coverage_notes(
        askable: list[Dependency],
        ctx: ScanContext,
        findings: list[Finding],
        over_ceiling: int,
        private_images: list[Dependency],
        ran_out_of_time: int,
        unanswered: list[str],
        unit: GraphUnit,
        unsupported: list[str],
    ) -> None:
        """What the scan could not ask the registries, said as operational findings: answers that never came, ecosystems no registry covers, and dependencies left unasked for the query ceiling, the time budget or a private image."""
        if unanswered:
            # One aggregated report rather than one per package: an offline
            # runner would otherwise produce a finding for every dependency in
            # the graph, and a report nobody reads is the same as no report.
            # It is still reported, because "we could not ask" and "the answer
            # was no" are different facts.
            findings.append(
                RegistryFinding.finding(
                    "OPERATIONAL.REGISTRY.UNREACHABLE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{len(unanswered)} of {len(askable)} package(s) could not be "
                        f"checked against their registry, so withdrawal, distance and "
                        f"hash verification did not run for them. First: {unanswered[0]}"
                    ),
                    degrades_coverage=True,
                )
            )

        if unsupported:
            counted = sum(1 for d in unit.dependencies if d.ecosystem in unsupported and d.version)
            findings.append(
                RegistryFinding.finding(
                    "OPERATIONAL.REGISTRY.NO_SOURCE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"--online has no registry configured for "
                        f"{', '.join(unsupported)}, so withdrawal, distance, hash and "
                        f"provenance checks did not run for {counted} package(s). Only "
                        f"{' and '.join(sorted(REGISTRY_ECOSYSTEMS))} are asked. Those "
                        f"packages were not checked and found clean; they were not "
                        f"checked."
                    ),
                    degrades_coverage=True,
                )
            )

        if over_ceiling or ran_out_of_time or private_images:
            reasons = []
            if over_ceiling:
                reasons.append(f"{over_ceiling} past the {MAX_QUERIES}-query ceiling for one scan")
            if ran_out_of_time:
                reasons.append(f"{ran_out_of_time} when the scan's time budget ran out")
            if private_images:
                reasons.append(
                    f"{len(private_images)} image(s) on a registry an organisation runs "
                    f"({private_images[0].name.split('/', 1)[0]}), which answers only with credentials"
                )
            findings.append(
                RegistryFinding.finding(
                    "OPERATIONAL.REGISTRY.NOT_ASKED.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{over_ceiling + ran_out_of_time + len(private_images)} of {len(askable) + len(private_images)} package(s) "
                        f"were never asked about: {', and '.join(reasons)}. Nothing is "
                        f"known about those versions -- they were not checked and found "
                        f"clean."
                    ),
                    degrades_coverage=True,
                )
            )

    def _manifest_findings(self, unit: FileUnit, ctx: ScanContext) -> list[Finding]:
        """Whether this project's manifest and the registry agree on the source.

        Silent unless every part of the question has an answer: the file is a
        manifest, it names a package, the package declares a repository, the
        registry knows the name, the registry records a repository of its own,
        and both reduce to a forge, an owner and a name. Any gap means the
        comparison was not made, and a finding claiming otherwise would be
        asserting a disagreement between two things one of which was never
        read.
        """
        from cordon_scanner.intel.registries.registry_client import RegistryClient, RegistryError

        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None or ecosystem_id not in REGISTRY_ECOSYSTEMS:
            return []

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return []

        manifest = ecosystem.parse_manifest(unit.content)
        if manifest.parse_error or manifest.private or not manifest.name:
            return []

        declared = RegistryEvidence.repository_identity(manifest.repository)
        if declared is None:
            return []

        # Counted after every cheap reason to stay quiet, so the budget is
        # spent on manifests a question could actually be asked about.
        if self._manifests_asked >= MAX_MANIFEST_QUERIES:
            return []
        self._manifests_asked += 1

        try:
            observed = RegistryClient.facts(ecosystem_id, manifest.name, manifest.version)
        except RegistryError:
            # A name the registry cannot answer about is the ordinary case for
            # an unpublished project, and is already reported in aggregate by
            # the graph pass. Reporting it again per manifest would drown the
            # thing this method exists to say.
            return []

        published = RegistryEvidence.repository_identity(observed.repository)
        if published is None or published == declared:
            return []

        detail = (
            f"{unit.path} says {manifest.name} is built from "
            f"{'/'.join(declared)}, and the {ecosystem_id} registry records "
            f"{'/'.join(published)} for that package. Reviewers who follow the "
            f"link in the manifest are reading a different repository from the "
            f"one the published package names."
        )
        return [
            RegistryFinding.finding(
                "SUSPECT.PACKAGE.REPOSITORY.001",
                ctx,
                dependency=None,
                detail=detail,
                path=unit.path,
            )
        ]

    @staticmethod
    def _order(dependencies: tuple[Dependency, ...]) -> list[Dependency]:
        """Every dependency, in the order requests should be spent on them.

        Direct first, then by depth. A ceiling applied to this order spends the
        budget where an answer is most likely to matter, and the caller reports
        how much of the list it did not reach.
        """
        return sorted(dependencies, key=lambda d: (not d.direct, d.depth, d.purl))

    def _compare(
        self, dependency: Dependency, observed: object, ctx: ScanContext
    ) -> Iterable[Finding]:
        from cordon_scanner.intel.registries.registry_client import PackageFacts

        if not isinstance(observed, PackageFacts):  # pragma: no cover - defensive
            return

        unvetted = self._unvetted(dependency, observed)
        if unvetted:
            yield RegistryFinding.finding(
                "SUSPECT.DEPENDENCY.UNVETTED.001", ctx, dependency=dependency, detail=unvetted
            )

        if observed.yanked and self._withdrawal_applies(dependency):
            # Who withdrew it is the registry's to say: "archived by CRAN" is CRAN's act, and "not
            # a version CRAN published" is no withdrawal at all. Only a bare yank (npm, PyPI) is
            # the publisher's.
            reason = observed.yanked_reason or ""
            label = f"{dependency.name}@{dependency.version}"
            yield RegistryFinding.finding(
                "SUSPECT.DEPENDENCY.YANKED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{label} is {reason}, and this lockfile pins it"
                    if reason.startswith("not a ")
                    else f"{label} was withdrawn ({reason}), and this lockfile still pins it"
                    if reason
                    else f"{label} was withdrawn by its publisher, and this lockfile still pins it"
                ),
            )

        borrowed = self._starjacked(dependency, observed)
        if borrowed:
            yield RegistryFinding.finding(
                "SUSPECT.PACKAGE.STARJACKING.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}, first published {str(observed.first_published)[:10]}, names "
                    f"{borrowed} as its repository: the repository of the popular package of that name, "
                    f"not of {dependency.name}"
                ),
            )

        if observed.deprecated and dependency.deprecated:
            pass  # the lockfile already said so, offline: POLICY.DEPENDENCY.ABANDONED.001
        elif observed.deprecated:
            notice = RegistryNotices.clean(observed.deprecated)
            security = RegistryNotices.cites_security(notice)
            yield RegistryFinding.finding(
                "SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001"
                if security
                else "POLICY.DEPENDENCY.DEPRECATED.001",
                ctx,
                dependency=dependency,
                detail=f"{dependency.name}@{dependency.version} is deprecated by its publisher: \u201c{notice}\u201d",
            )
        elif RegistryNotices.older_than(observed.last_published, UNMAINTAINED_DAYS):
            yield RegistryFinding.finding(
                "POLICY.DEPENDENCY.UNMAINTAINED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name} last published a release on "
                    f"{str(observed.last_published)[:10]}, more than five years ago"
                ),
            )

        # What the comparison concluded, for the dependency's record: a match is a positive
        # result no finding states.
        verdict = self._digest_verdict(dependency, observed.digests)
        if verdict is not None:
            ctx.checks.record(dependency.purl, "integrity", verdict)
        ctx.checks.record(dependency.purl, "registry", "found")

        if self._digest_conflict(dependency, observed.digests):
            yield RegistryFinding.finding(
                "SUSPECT.PROVENANCE.MISMATCH.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"the hash recorded for {dependency.name}@{dependency.version} "
                    f"is not among the hashes the registry publishes for that version"
                ),
            )

        if observed.attested_versions >= MIN_ATTESTED_SIBLINGS and not observed.attested:
            yield RegistryFinding.finding(
                "SUSPECT.PACKAGE.PROVENANCE.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{observed.attested_versions} earlier release(s) of "
                    f"{dependency.name} were published with build provenance and "
                    f"{dependency.version} was not. The package was already "
                    f"attesting when this one shipped, so this is not a pin that "
                    f"predates the practice -- it is a release that can be traced "
                    f"to no commit and no workflow while its siblings can"
                ),
            )

        if observed.latest and dependency.version and observed.latest != dependency.version:
            behind = self._major_distance(dependency.version, observed.latest)
            if behind >= ctx.config.policy.max_major_drift:
                yield RegistryFinding.finding(
                    "POLICY.DEPENDENCY.DOWNGRADE.001",
                    ctx,
                    dependency=dependency,
                    detail=(
                        f"{dependency.name} is pinned to {dependency.version} while "
                        f"{observed.latest} is current, {behind} major versions ahead"
                    ),
                )

    @staticmethod
    def _starjacked(dependency: Dependency, observed: PackageFacts) -> str:
        """The borrowed repository (`forge/owner/name`), or "" when the claim is the package's own.

        Fires only for a young package whose repository's name is a DIFFERENT popular package in the
        same ecosystem, and never when the repository is the package's own name, a prefix of it, or
        its npm scope: `@babel/plugin-x` pointing at `babel/babel` is a monorepo, not a squat.
        """
        from cordon_scanner.intel.registries.popular import PackageIntel

        identity = RegistryEvidence.repository_identity(observed.repository)
        first = observed.first_published
        if identity is None or not first or RegistryNotices.older_than(first, STARJACK_YOUNG_DAYS):
            return ""
        forge, owner, repo = identity
        repo, owner = repo.lower().removesuffix(".git"), owner.lower()
        name = dependency.name.lower()
        scope, _, base = name.rpartition("/")
        scope = scope.lstrip("@")
        if repo in (base, scope) or owner == scope or base.startswith(repo):
            return ""
        if repo not in PackageIntel.POPULAR_PACKAGES.get(dependency.ecosystem, frozenset()):
            return ""
        return f"{forge}/{owner}/{repo}"

    @staticmethod
    def _digest_verdict(dependency: Dependency, published: tuple[str, ...]) -> str | None:
        """`verified` when the recorded hash is among the registry's for its algorithm,
        `mismatched` when the registry publishes that algorithm and not this value, None when
        nothing comparable exists (the record keeps `recorded`)."""
        recorded = RegistryEvidence._canonical_digest(dependency.integrity)
        if recorded is None or not published:
            return None
        algorithm, digest = recorded
        comparable = {
            parsed[1]
            for entry in published
            if (parsed := RegistryEvidence._canonical_digest(entry)) is not None
            and parsed[0] == algorithm
        }
        if not comparable:
            return None
        return "verified" if digest in comparable else "mismatched"

    @staticmethod
    def _digest_conflict(dependency: Dependency, published: tuple[str, ...]) -> bool:
        """Whether the recorded hash contradicts every published one.

        Absence is not a conflict. A lockfile with no hash is already reported
        by the offline integrity rule, and a registry that publishes none
        cannot contradict anything -- treating either as a mismatch would make
        this rule fire on the ordinary case and mean nothing on the real one.

        Neither is a value that is not a registry digest at all. Yarn Berry\'s
        `checksum:` is a hash of its own cache entry, prefixed with the cache
        key (`10c0/...`), and it can never equal the tarball hash npm serves --
        so comparing the two reported every dependency of every Berry lockfile
        as a CRITICAL mismatch. Only a value that resolves to a known algorithm
        and a digest of that algorithm\'s length is a claim about the artefact.

        Comparison is per algorithm. npm publishes a sha512 `integrity` beside a
        sha1 `shasum`, and a lockfile recording one of the two contradicts
        neither: a sha1 that does not appear among the sha512s is the ordinary
        case, not evidence.
        """
        recorded = RegistryEvidence._canonical_digest(dependency.integrity)
        if recorded is None or not published:
            return False

        algorithm, digest = recorded
        comparable: set[str] = set()
        for entry in published:
            parsed = RegistryEvidence._canonical_digest(entry)
            if parsed is not None and parsed[0] == algorithm:
                comparable.add(parsed[1])
        if not comparable:
            return False
        return digest not in comparable

    @staticmethod
    def _major_distance(pinned: str, latest: str) -> int:
        """How many major versions separate two version strings.

        Deliberately crude. Version schemes differ enough that a precise
        comparison needs each ecosystem's own rules, and the question here is
        only "is this pin far behind", which the leading number answers well
        enough to prompt a look. Anything unparseable returns zero rather than
        guessing.
        """

        def leading(value: str) -> int | None:
            head = value.lstrip("v=^~ ").split(".", 1)[0]
            digits = "".join(c for c in head if c.isdigit())
            return int(digits) if digits else None

        first, second = leading(pinned), leading(latest)
        if first is None or second is None:
            return 0
        return max(0, second - first)

    LOW_DOWNLOADS = 100
    _AFFIXES = frozenset(
        {"cli", "utils", "util", "tools", "tool", "helper", "helpers", "sdk", "api", "client", "lib", "core",
         "py", "python", "js", "node", "plugin", "wrapper", "fix", "patch", "pro", "plus", "lite", "official", "dev"}
    )  # fmt: skip

    @classmethod
    def _unvetted(cls, dependency: Dependency, observed: object) -> str | None:
        """The shape a slopsquatted package has: new, no source repository, and either barely
        downloaded or named by adding a generic affix to an established package."""
        from cordon_scanner.intel.registries.real import RealPackages
        from cordon_scanner.intel.registries.registry_client import (
            NEW_PACKAGE_DAYS,
            PackageFacts,
            RegistryClient,
        )

        if not isinstance(observed, PackageFacts) or observed.repository:
            return None
        if not RegistryClient._younger_than(observed.first_published, NEW_PACKAGE_DAYS):
            return None
        established = RealPackages.real_packages(dependency.ecosystem)
        name = dependency.name.lower()
        if name in established:
            return None
        tokens = [t for t in re.split(r"[-_.]", name.split("/")[-1]) if t]
        borrowed = next((t for t in tokens if t in established and len(t) >= 4), None)
        affixed = borrowed is not None and any(t in cls._AFFIXES for t in tokens if t != borrowed)
        quiet = (
            observed.weekly_downloads is not None and observed.weekly_downloads < cls.LOW_DOWNLOADS
        )
        if not (affixed or quiet):
            return None
        signals = [
            f"first published {(observed.first_published or '')[:10]}",
            "no source repository on record",
        ]
        if quiet:
            signals.append(f"{observed.weekly_downloads} downloads last week")
        if affixed:
            signals.append(
                f"named by adding a generic word to the established package {borrowed!r}"
            )
        return (
            f"{dependency.name} has the shape of a package registered to catch a name an AI assistant "
            f"invented: {'; '.join(signals)}."
        )

    #: Registries that mark a withdrawal only by dropping the version from their public list.
    ABSENCE_IS_WITHDRAWAL = frozenset({"rubygems", "composer"})
    #: Where Packagist sends Composer for a public package: the forge's own archive service.
    FORGE_ARCHIVE_HOSTS = frozenset(
        {"api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"}
    )

    @classmethod
    def _withdrawal_applies(cls, dependency: Dependency) -> bool:
        """Whether the registry's withdrawal answer is about this dependency.

        RubyGems and Packagist say a version was withdrawn only by no longer listing it, and a
        version from a private source is never on the public list in the first place. Reporting
        that as a withdrawal would put a finding on every private gem or package pinned under
        --online, so for those two the answer counts only when the lockfile says the version came
        from the public registry or its forge archive, or records no source at all.
        """
        if dependency.ecosystem not in cls.ABSENCE_IS_WITHDRAWAL:
            return True

        from cordon_scanner.intel.registries.registry_hosts import PUBLIC_HOSTS

        resolved = dependency.resolved_from or ""
        if not resolved.startswith(("http://", "https://")):
            return True
        host = urllib.parse.urlsplit(resolved).hostname or ""
        return host in PUBLIC_HOSTS or host in cls.FORGE_ARCHIVE_HOSTS

    @staticmethod
    def _resolved_privately(dependency: Dependency) -> bool:
        """The lockfile says this came from somewhere other than the public registry."""

        resolved = dependency.resolved_from or ""
        if resolved.startswith("registry:"):
            # A named registry the project configures (`registry:internal`, a Conan user/channel).
            from cordon_scanner.ecosystems.base import PUBLIC_REGISTRY_NAMES

            return resolved.removeprefix("registry:").lower() not in PUBLIC_REGISTRY_NAMES
        if not resolved.startswith(("http://", "https://")):
            return False
        host = urllib.parse.urlsplit(resolved).hostname or ""
        from cordon_scanner.intel.registries.registry_hosts import PUBLIC_HOSTS

        return host not in {
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "pypi.org",
            "files.pythonhosted.org",
            *PUBLIC_HOSTS,
        }


STARJACK_YOUNG_DAYS = 90
"""A package younger than this that names a popular project's repository is reported."""

UNMAINTAINED_DAYS = 5 * 365 + 1
"""Five years without a release: Socket's threshold, and long enough that a stable, finished
package is rarely caught by it."""


__all__ = [
    "CONFUSABLE_ECOSYSTEMS",
    "MAX_MANIFEST_QUERIES",
    "MAX_QUERIES",
    "MIN_ATTESTED_SIBLINGS",
    "REGISTRY_ECOSYSTEMS",
    "STARJACK_YOUNG_DAYS",
    "UNMAINTAINED_DAYS",
    "RegistryDetector",
]
