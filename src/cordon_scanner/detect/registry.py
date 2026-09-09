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

import urllib.parse
from typing import TYPE_CHECKING

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
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import Unit

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

REGISTRY_ECOSYSTEMS = frozenset({"npm", "pypi"})
"""Ecosystems whose registry this can ask. Kept beside the client's own host
map so a manifest for an ecosystem with no configured registry is skipped
before a request is built rather than after it fails."""

FORGE_SHORTHANDS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
    "gist": "gist.github.com",
}
"""npm accepts `github:owner/repo` and friends in the `repository` field, and
plenty of packages use them. Expanded here so a shorthand and the HTTPS URL it
abbreviates compare as the same repository, which is what they are."""


def repository_identity(url: str | None) -> tuple[str, str, str] | None:
    """A repository URL reduced to the forge, owner and name it points at.

    The same repository is written half a dozen ways: `git@github.com:o/r.git`,
    `git+https://github.com/o/r.git`, `github:o/r`, a bare `o/r`, and a link
    into a subdirectory of a monorepo. All of those are one repository, and a
    comparison that treated them as different would report a mismatch on
    essentially every package that uses anything but the plain HTTPS form.

    So: the transport prefix goes, credentials go, the query and fragment go,
    the `.git` suffix goes, and only the first two path segments are kept --
    everything after `owner/repo` is a path *inside* the repository, not part of
    its identity.

    Returns `None` when the string does not resolve to all three parts.
    Comparing an unresolvable claim against anything would be guessing, and the
    caller is expected to stay quiet rather than guess.
    """
    if not url:
        return None

    text = url.strip()
    if not text:
        return None

    # `git+https://...`, `git+ssh://...`: the transport is a packaging detail.
    if text.startswith("git+"):
        text = text[4:]

    # An npm shorthand, or a bare `owner/repo` which npm reads as GitHub.
    scheme, separator, remainder = text.partition(":")
    if separator and scheme.lower() in FORGE_SHORTHANDS and not remainder.startswith("//"):
        text = f"https://{FORGE_SHORTHANDS[scheme.lower()]}/{remainder.lstrip('/')}"
    elif "://" not in text and "@" not in text:
        segments = [part for part in text.split("/") if part]
        if len(segments) == 2 and "." not in segments[0]:
            text = f"https://github.com/{segments[0]}/{segments[1]}"

    # `git@host:owner/repo`, the SCP-style form URL parsers do not accept.
    if "://" not in text and "@" in text:
        _, _, tail = text.partition("@")
        host, separator, path = tail.partition(":")
        if separator:
            text = f"https://{host}/{path.lstrip('/')}"

    parsed = urllib.parse.urlsplit(text if "://" in text else f"https://{text}")
    host = parsed.hostname or ""
    if not host:
        return None
    if host.startswith("www."):
        host = host[4:]

    segments = [part for part in parsed.path.split("/") if part]
    if len(segments) < 2:
        return None

    owner, name = segments[0], segments[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        return None

    return (host.lower(), owner.lower(), name.lower())


MIN_ATTESTED_SIBLINGS = 3
"""How many *earlier* attested releases make an unattested one worth reporting.

One is a project that tried provenance once. A handful is a project that
publishes with it, and a release that skipped it did not come from the pipeline
the others came from.

Earlier ones only, which the client counts. A package that adopted provenance
last month has an attested latest and an unattested everything-else, and
counting totals would put this finding on every pin that predates the practice
-- `requests==2.31.0` among them, which skipped nothing."""


NETWORK_CAVEAT = (
    "This finding came from a live registry query. It is not reproducible from "
    "the repository alone, and rerunning the scan offline will not produce it."
)


class RegistryDetector(BaseDetector):
    """Enriches the dependency graph with what the registry says."""

    id = "registry"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, dependencies=True, network=True)

    def __init__(self) -> None:
        self._manifests_asked = 0

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies) and not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.YANKED.001",
                title="Dependency pins a version its publisher withdrew",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                remediation=(
                    "Move off the withdrawn version. A release is yanked because "
                    "its publisher decided nobody should be installing it."
                ),
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.DOWNGRADE.001",
                title="Dependency pins a version far behind the current release",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=RegistryDetector.id,
                remediation=(
                    "Confirm the pin is deliberate. A distant pin is ordinary in a "
                    "conservative project and is also what a downgrade attack "
                    "produces."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PROVENANCE.MISMATCH.001",
                title="Lockfile hash disagrees with the registry",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                remediation=(
                    "Do not install. One of the two records is not describing the "
                    "artefact that will arrive, and until that is resolved neither "
                    "can be trusted."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.REPOSITORY.001",
                title="Package claims a source repository the registry does not record",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                remediation=(
                    "Establish which repository the published artefact was "
                    "actually built from. Reading the linked source proves "
                    "nothing about the package while the two disagree."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.PROVENANCE.001",
                title="Version published without the provenance its package normally carries",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                remediation=(
                    "Establish where this release was built. Its siblings can "
                    "be traced to a commit and a workflow and this one cannot, "
                    "which is the difference a compromised publishing token "
                    "produces."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.REGISTRY.UNREACHABLE.001",
                title="Registry could not be asked about a dependency",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=RegistryDetector.id,
                remediation=(
                    "Rerun when the registry is reachable, or accept that these checks did not run."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.offline:
            return ()
        if isinstance(unit, FileUnit):
            return self._manifest_findings(unit, ctx)
        if not isinstance(unit, GraphUnit):
            return ()

        from cordon_scanner.intel.registry_client import RegistryError, facts

        findings: list[Finding] = []
        unanswered: list[str] = []

        for dependency in self._to_ask(unit.dependencies):
            try:
                observed = facts(dependency.ecosystem, dependency.name, dependency.version)
            except RegistryError as exc:
                unanswered.append(f"{dependency.name}: {exc}")
                continue
            findings.extend(self._compare(dependency, observed, ctx))

        if unanswered:
            # One aggregated report rather than one per package: an offline
            # runner would otherwise produce a finding for every dependency in
            # the graph, and a report nobody reads is the same as no report.
            # It is still reported, because "we could not ask" and "the answer
            # was no" are different facts.
            findings.append(
                self._finding(
                    "OPERATIONAL.REGISTRY.UNREACHABLE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{len(unanswered)} package(s) could not be checked against "
                        f"their registry, so withdrawal, distance and hash "
                        f"verification did not run for them. First: {unanswered[0]}"
                    ),
                )
            )
        return findings

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
        from cordon_scanner.intel.registry_client import RegistryError, facts

        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None or ecosystem_id not in REGISTRY_ECOSYSTEMS:
            return []

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return []

        manifest = ecosystem.parse_manifest(unit.content)
        if manifest.parse_error or manifest.private or not manifest.name:
            return []

        declared = repository_identity(manifest.repository)
        if declared is None:
            return []

        # Counted after every cheap reason to stay quiet, so the budget is
        # spent on manifests a question could actually be asked about.
        if self._manifests_asked >= MAX_MANIFEST_QUERIES:
            return []
        self._manifests_asked += 1

        try:
            observed = facts(ecosystem_id, manifest.name, manifest.version)
        except RegistryError:
            # A name the registry cannot answer about is the ordinary case for
            # an unpublished project, and is already reported in aggregate by
            # the graph pass. Reporting it again per manifest would drown the
            # thing this method exists to say.
            return []

        published = repository_identity(observed.repository)
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
            self._finding(
                "SUSPECT.PACKAGE.REPOSITORY.001",
                ctx,
                dependency=None,
                detail=detail,
                path=unit.path,
            )
        ]

    @staticmethod
    def _to_ask(dependencies: tuple[Dependency, ...]) -> list[Dependency]:
        """Which packages to spend a request on, direct ones first."""
        ordered = sorted(dependencies, key=lambda d: (not d.direct, d.depth, d.purl))
        return [d for d in ordered if d.version][:MAX_QUERIES]

    def _compare(
        self, dependency: Dependency, observed: object, ctx: ScanContext
    ) -> Iterable[Finding]:
        from cordon_scanner.intel.registry_client import PackageFacts

        if not isinstance(observed, PackageFacts):  # pragma: no cover - defensive
            return

        if observed.yanked:
            reason = f" ({observed.yanked_reason})" if observed.yanked_reason else ""
            yield self._finding(
                "SUSPECT.DEPENDENCY.YANKED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{dependency.version} was withdrawn by its "
                    f"publisher{reason}, and this lockfile still pins it"
                ),
            )

        if self._digest_conflict(dependency, observed.digests):
            yield self._finding(
                "SUSPECT.PROVENANCE.MISMATCH.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"the hash recorded for {dependency.name}@{dependency.version} "
                    f"is not among the hashes the registry publishes for that version"
                ),
            )

        if observed.attested_versions >= MIN_ATTESTED_SIBLINGS and not observed.attested:
            yield self._finding(
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
            if behind >= 2:
                yield self._finding(
                    "POLICY.DEPENDENCY.DOWNGRADE.001",
                    ctx,
                    dependency=dependency,
                    detail=(
                        f"{dependency.name} is pinned to {dependency.version} while "
                        f"{observed.latest} is current, {behind} major versions ahead"
                    ),
                )

    @staticmethod
    def _digest_conflict(dependency: Dependency, published: tuple[str, ...]) -> bool:
        """Whether the recorded hash contradicts every published one.

        Absence is not a conflict. A lockfile with no hash is already reported
        by the offline integrity rule, and a registry that publishes none
        cannot contradict anything -- treating either as a mismatch would make
        this rule fire on the ordinary case and mean nothing on the real one.
        """
        recorded = (dependency.integrity or "").strip()
        if not recorded or not published:
            return False

        # Lockfiles write hashes in several shapes: `sha256-<base64>`,
        # `sha256:<hex>`, or a bare digest. Comparison is on the digest itself,
        # since the framing differs by tool and says nothing about the artefact.
        def bare(value: str) -> str:
            for separator in ("-", ":", "="):
                head, found, tail = value.partition(separator)
                if found and head.lower().startswith(("sha", "md5")):
                    return tail.strip().lower()
            return value.strip().lower()

        return bare(recorded) not in {bare(entry) for entry in published}

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

    def _finding(
        self,
        rule_id: str,
        ctx: ScanContext,
        *,
        dependency: Dependency | None,
        detail: str,
        path: str | None = None,
    ) -> Finding:
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        if path is None:
            path = (dependency.declared_in or dependency.project or "") if dependency else ""

        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=path, line=1),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("source", "registry"),),
            ),
            remediation=declared.remediation,
            explanation=Explanation(
                summary=detail,
                matched_rule=rule_id,
                escalations=(NETWORK_CAVEAT,),
            ),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=self.id,
            always_report=declared.category is Category.OPERATIONAL,
        )


__all__ = [
    "MAX_MANIFEST_QUERIES",
    "MAX_QUERIES",
    "MIN_ATTESTED_SIBLINGS",
    "REGISTRY_ECOSYSTEMS",
    "RegistryDetector",
    "repository_identity",
]
