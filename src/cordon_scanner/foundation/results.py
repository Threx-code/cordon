"""What a scan reports beyond its findings: the repository scanned and its projects, the install hooks
they declare, every dependency with what each check concluded, the languages present, the scan's
statistics, and the result that holds them all with the findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

from cordon_scanner.foundation.models import Category, Confidence, Finding, Hook, Scope, Severity


@dataclass(frozen=True, slots=True)
class LanguageStat:
    language: str
    files: int
    bytes: int
    share: float
    evidence: tuple[str, ...] = ()
    """What led to this conclusion. Inventory that cannot explain itself cannot
    be debugged when it is wrong."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "files": self.files,
            "bytes": self.bytes,
            "share": round(self.share, 4),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class Project:
    """A subtree with its own manifest.

    A monorepo is N projects, not one repository with a mixed file list. Modelling
    it that way is what makes detector selection correct: a Python service and a
    TypeScript front end in the same tree get different detectors, different
    ecosystem parsers and different language rules, scoped to their own subtree.

    Without this, a polyglot repository gets the union of every rule applied to
    every file, which produces both false positives (JavaScript rules firing on
    Python strings) and false negatives (a rule disabled because it was noisy
    somewhere unrelated).
    """

    path: str
    ecosystem: str | None = None
    manifests: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    framework: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        for key in ("name", "ecosystem", "framework"):
            value = getattr(self, key)
            if value:
                out[key] = value
        for key in ("manifests", "lockfiles", "languages"):
            value = getattr(self, key)
            if value:
                out[key] = list(value)
        return out


@dataclass(frozen=True, slots=True)
class Repository:
    """What the scan target actually is.

    Produced by the inventory phase and consumed by every detector's
    applicability check, which is what makes scanner selection automatic rather
    than configured. A user should not have to declare that their repository
    contains Terraform; the tool should observe it and act accordingly.
    """

    root: str
    """Absolute path to the scan target.

    Serialised as its basename. `Location.path` promises results are "safe to
    publish", and the absolute root is what makes them not: in CI it exposes
    runner directory layouts, internal project names and sometimes usernames,
    into artefacts routinely uploaded to third parties and attached to pull
    requests. The name of the thing scanned is the part that carries meaning
    across machines."""

    is_git: bool = False

    scanned_repository_root: bool = False
    """Whether the scan target IS the repository root, not a directory inside one.

    `is_git` answers "is there a repository above this", which is a different
    question and was being used for this one. Scanning
    `corpus/malicious/acme-telemetry` from inside a checkout reports `is_git` true,
    because a repository is above it -- so a check that read `is_git` as "this is
    the project being developed here" treated every downloaded package, extracted
    archive and audited subdirectory inside any checkout as first-party code.

    Kept out of `to_dict` deliberately. It is an input to severity, not a fact
    about the code that a consumer of the report needs; `root` and `revision`
    already say what was scanned.
    """

    revision: str | None = None
    remote: str | None = None
    branch: str | None = None
    languages: tuple[LanguageStat, ...] = ()
    projects: tuple[Project, ...] = ()
    ecosystems: tuple[str, ...] = ()
    ci_systems: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    containers: tuple[str, ...] = ()
    iac: tuple[str, ...] = ()
    hooks: tuple[Hook, ...] = ()
    file_count: int = 0
    total_bytes: int = 0

    @property
    def public_root(self) -> str:
        """The scan target's name, without the path that led to it."""
        cleaned = self.root.replace("\\", "/").rstrip("/")
        return cleaned.rpartition("/")[2] or cleaned or "."

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.public_root,
            "is_git": self.is_git,
            "revision": self.revision,
            "remote": self.remote,
            "branch": self.branch,
            "languages": [x.to_dict() for x in self.languages],
            "projects": [p.to_dict() for p in self.projects],
            "ecosystems": list(self.ecosystems),
            "ci_systems": list(self.ci_systems),
            "build_systems": list(self.build_systems),
            "containers": list(self.containers),
            "iac": list(self.iac),
            "hooks": [h.to_dict() for h in self.hooks],
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class Dependency:
    """One node in the resolved dependency graph.

    Built by parsing the lockfile, never by invoking the package manager and
    never by resolving over the network. Running the ecosystem's own resolver to
    learn the graph would mean executing untrusted tooling against
    attacker-controlled metadata, inside the tool whose entire purpose is to
    avoid exactly that. It would also make results non-reproducible, since a
    resolver consults a live registry.

    ``integrity`` is the lockfile's own hash for the artefact. Comparing it
    against a baseline enables one of the highest-signal checks available: an
    integrity hash that changed while the version did not means the registry
    content was replaced under a name that had already been reviewed.
    """

    purl: str
    """Package URL. The cross-ecosystem identity, so findings, intelligence and
    advisories can be correlated without per-ecosystem special cases."""

    ecosystem: str
    name: str
    version: str | None = None
    direct: bool = False

    local: bool = False
    """This dependency is the project's own code: a workspace member, a path
    dependency, a linked package. It has no registry hash because the bytes are in
    the repository and are reviewed as source. Carried from `LockEntry.local`, where
    the reasoning is written down."""

    depth: int = 0
    scope: Scope = Scope.RUNTIME
    resolved_from: str | None = None
    integrity: str | None = None
    parents: tuple[str, ...] = ()
    declared_spec: str | None = None
    project: str | None = None

    repository: str | None = None
    """The source repository this package claims, as its manifest records it.

    Carried so it can be compared with what the registry says the artefact was
    built from. The two disagreeing is the shape of a package that points
    reviewers at code it was not built from: reading the linked repository
    proves nothing about what was published, and the link is the thing most
    people check."""

    declared_in: str | None = None
    """The lockfile that resolved this dependency.

    Findings about a dependency had `Location(path=dep.project or "")`, and for
    a single-project repository `project` is None -- so every typosquat,
    integrity and source finding carried an empty `artifactLocation.uri` in
    SARIF. GitHub code scanning cannot anchor an alert to an empty URI, so the
    whole dependency layer was invisible in the integration that is the
    product's main CI story."""

    license: str | None = None
    """As the resolving lockfile declares it, verbatim. `None` means the
    format this dependency was resolved from does not carry license data
    offline, not that the dependency has no license -- `detect/license.py`
    is the only reader, and it treats the two identically (nothing to
    report) rather than guessing at the difference."""

    platform: tuple[str, ...] = ()
    """The conditions under which this dependency applies, as the file wrote them: an
    environment marker (`sys_platform == "win32"`), npm's `os`/`cpu`, a Cargo `cfg(...)` target,
    a .NET target framework, a Gem platform. Empty means unconditional or not recorded."""

    manifest_path: str | None = None
    """The manifest that declared it, when it is direct and a manifest beside the lockfile names
    it. `declared_in` is the file that resolved it; the two are different questions."""
    manifest_line: int | None = None
    lockfile_line: int | None = None

    dependency_path: tuple[str, ...] = ()
    """One chain of package names from a direct dependency down to this one: how it arrived."""

    advisory_status: str = "not_checked"
    malware_status: str = "not_checked"
    integrity_status: str = "not_checked"
    provenance_status: str = "not_checked"
    licence_status: str = "not_checked"
    """What each check concluded, never one boolean. "No vulnerability found" and "the check
    did not run" are different answers; see `core/inventory.py` for every value and its meaning."""

    finding_ids: tuple[str, ...] = ()
    """Fingerprints of the findings about this dependency."""

    resolution_note: str | None = None
    """Why it is unresolved, when the parser or engine knows better than the generic reason."""

    resolved_by: str | None = None
    """What fixed the version when it was not the dependency's own file: `the constraints file
    constraints.txt` for a range a pip `-c` pin resolves."""

    alias: str | None = None
    """The name the project declared it under, when that is not the package's own."""

    bundled: bool = False
    """It arrives inside another package's archive and is verified by that archive's hash. See
    `LockEntry.bundled`."""

    signatures: tuple[str, ...] = ()
    """Detached signatures recorded with the installed package, over `signed`. See
    `LockEntry.signatures`. Not in any report: the provenance detector verifies them."""

    signed: bytes | None = field(default=None, repr=False)
    """The bytes `signatures` cover. See `LockEntry.signed`."""

    signature_sources: tuple[str, ...] = ()
    """Where the declaration says its signatures are. See `DeclaredDependency.signature_sources`."""

    extras: tuple[str, ...] = ()
    """Optional features requested (`requests[socks]`, Cargo features). See
    `DeclaredDependency.extras`."""

    editable: bool = False
    """Installed in place from a working tree (`pip install -e`)."""

    exclusions: tuple[str, ...] = ()
    """Transitive dependencies the declaration excludes (Maven `<exclusions>`)."""

    forced_by: str | None = None
    """The override that pins this version across the tree (npm `overrides`, Yarn `resolutions`,
    pnpm `pnpm.overrides`, Composer and Cargo equivalents), as `<spec> in <file>`. An upgrade
    anywhere else does not move it; the override must change."""

    deprecated: str | None = None
    """What the lockfile records about the package's maintenance, when it does: Composer writes
    `"abandoned": "symfony/mailer"` for a package its maintainer abandoned. Offline evidence the
    registry check would otherwise need the network for."""

    def _resolved_by_lockfile(self) -> bool:
        """Whether `declared_in` is a lockfile (it may also be the manifest: a pinned
        `requirements.txt` is both)."""
        from cordon_scanner.foundation.dependencies import DependencyResolution

        return DependencyResolution.by_lockfile(self)

    @property
    def namespace(self) -> str | None:
        from cordon_scanner.foundation.dependencies import DependencyIdentity

        # A Homebrew formula from a named tap is recorded by its own name, its tap the namespace
        # its full name (`user/repo/name`, kept as the alias) carries.
        name = self.alias if self.ecosystem == "homebrew" and self.alias else self.name
        return DependencyIdentity.namespace(self.ecosystem, name)

    @property
    def source(self) -> tuple[str, str | None]:
        """`(source_type, source_url)`; the URL never carries credentials."""
        from cordon_scanner.foundation.dependencies import DependencySource

        return DependencySource.classify(self)

    @property
    def resolution(self) -> tuple[str, str]:
        """`(resolution_status, reason)`."""
        from cordon_scanner.foundation.dependencies import DependencyResolution

        return DependencyResolution.status(self)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "direct": self.direct,
            "depth": self.depth,
            "scope": str(self.scope),
        }
        for key in (
            "version",
            "resolved_from",
            "integrity",
            "declared_spec",
            "project",
            "declared_in",
            "license",
        ):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.parents:
            out["parents"] = list(self.parents)
        source_type, source_url = self.source
        status, reason = self.resolution
        # The shared dependency record: the same keys for every ecosystem.
        out["record"] = {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "declared_name": self.alias or self.name,
            "namespace": self.namespace,
            "version_constraint": self.declared_spec,
            "resolved_version": (self.version or None)
            if status in ("resolved", "partially_resolved")
            else None,
            "resolution_status": status,
            "resolution_reason": reason,
            "source_type": source_type,
            "source_url": source_url,
            "integrity": self.integrity,
            "direct": self.direct,
            "dependency_path": list(self.dependency_path or (self.name,)),
            "dependency_type": str(self.scope),
            "platform_constraints": list(self.platform),
            "manifest_location": (
                {"path": self.manifest_path, "line": self.manifest_line}
                if self.manifest_path
                else None
            ),
            "lockfile_location": (
                {"path": self.declared_in, "line": self.lockfile_line}
                if self._resolved_by_lockfile()
                else None
            ),
            "advisory_status": self.advisory_status,
            "malware_status": self.malware_status,
            "integrity_status": self.integrity_status,
            "provenance_status": self.provenance_status,
            "licence_status": self.licence_status,
            "findings": list(self.finding_ids),
            "overridden_by": self.forced_by,
            "deprecated": self.deprecated,
            "extras": list(self.extras),
            "editable": self.editable,
            "exclusions": list(self.exclusions),
        }
        return out


@dataclass(frozen=True, slots=True)
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    dependencies: int = 0
    rules_evaluated: int = 0
    duration_ms: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    archives_expanded: int = 0
    """Archives inside a directory scan that were opened and their members scanned."""
    archive_members: int = 0
    archive_ms: int = 0
    """Wall time spent expanding archives, so the cost of opening them is visible."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "archives_expanded": self.archives_expanded,
            "archive_members": self.archive_members,
            "archive_ms": self.archive_ms,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "dependencies": self.dependencies,
            "rules_evaluated": self.rules_evaluated,
            "duration_ms": self.duration_ms,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything a scan produced. The aggregate root of the domain.

    ``complete`` is the field a pipeline must be able to see. A scan that hit its
    timeout, or skipped files it could not read, is not a clean scan, and
    reporting it as one is a false negative dressed as a pass. Making
    completeness an explicit property with its own exit code lets a release
    pipeline demand a full scan while a pre-commit hook tolerates a partial one.

    ``rulepack_hash`` and ``config_hash`` make a result self-describing: months
    later it is still possible to say exactly which rules and which settings
    produced it, which is what auditability actually requires.
    """

    findings: tuple[Finding, ...] = ()
    repository: Repository | None = None
    dependencies: tuple[Dependency, ...] = ()
    stats: ScanStats = field(default_factory=ScanStats)
    complete: bool = True
    content_complete: bool = True
    """Every file's content was read (review 98, REC-5). `complete` is this AND `advisory_complete`,
    kept for every pipeline that already reads it."""
    advisory_complete: bool = True
    """Every dependency was checked against an advisory or registry source and the intel was
    current. Its absence is reported; it is no reason to call a package's content unread."""
    schema_version: int = 1
    engine_version: str = "0.0.0"
    rulepack_version: str = "0.0.0"
    rulepack_hash: str = ""
    config_hash: str = ""
    intel: dict[str, Any] | None = None
    """How current the threat intel behind this scan was: its source, age and feed serial.
    See `intel/feed.IntelStatus`. None for a result built outside a scan."""
    sources: tuple[tuple[str, str, str], ...] = ()
    """`(file, ecosystem, source)` for every package source a project configures -- a pip index,
    a Cargo registry or source replacement, a Composer repository, a NuGet feed -- with any
    credentials removed. Where resolution looks is what dependency confusion turns on."""
    image: dict[str, Any] | None = None
    """The scanned image's identity (`images.oci.ImageIdentity`): its ID and manifest digest, the
    names it was saved under, its layers, its platform and the base image its labels name."""
    target_kind: str = "source"
    """What was scanned: ``source`` (a directory or repository), ``image`` (a container image
    archive, read layer by layer), ``package`` (a published package's distribution archive),
    ``archive`` (any other archive), ``sbom`` (a bill of materials it was given) or ``host`` (an
    installed system, `scan --host`). Sent with an upload so the console can tell them apart."""
    verdict: dict[str, Any] | None = None
    """The package verdict (`core/verdict.py`): the features it read and, with a model shipped, its
    score and thresholds."""

    @property
    def active(self) -> tuple[Finding, ...]:
        """Findings that are not suppressed. What a policy gate evaluates."""
        return tuple(f for f in self.findings if not f.is_suppressed)

    @property
    def suppressed(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.is_suppressed)

    def by_severity(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.active:
            counts[finding.severity] += 1
        return counts

    def by_category(self) -> dict[Category, int]:
        counts = dict.fromkeys(Category, 0)
        for finding in self.active:
            counts[finding.category] += 1
        return counts

    def filter(
        self,
        *,
        min_severity: Severity | None = None,
        min_confidence: Confidence | None = None,
        categories: Sequence[Category] | None = None,
    ) -> ScanResult:
        selected = [
            f
            for f in self.findings
            if (min_severity is None or f.severity >= min_severity)
            and (min_confidence is None or f.confidence >= min_confidence)
            and (categories is None or f.category in categories)
        ]
        return replace(self, findings=tuple(selected))

    def sorted(self) -> ScanResult:
        return replace(self, findings=tuple(sorted(self.findings, key=Finding.sort_key)))

    def to_dict(self) -> dict[str, Any]:
        return (
            {
                "schema_version": self.schema_version,
                "engine_version": self.engine_version,
                "rulepack_version": self.rulepack_version,
                "rulepack_hash": self.rulepack_hash,
                "config_hash": self.config_hash,
                "complete": self.complete,
                "content_complete": self.content_complete,
                "advisory_complete": self.advisory_complete,
                "intel": self.intel,
                "stats": self.stats.to_dict(),
                "repository": self.repository.to_dict() if self.repository else None,
                "dependencies": [d.to_dict() for d in self.dependencies],
                "sources": [{"path": p, "ecosystem": e, "source": s} for p, e, s in self.sources],
                "findings": [f.to_dict() for f in self.findings],
            }
            | ({"image": self.image} if self.image is not None else {})
            | ({"verdict": self.verdict} if self.verdict is not None else {})
        )


__all__ = ["Dependency", "LanguageStat", "Project", "Repository", "ScanResult", "ScanStats"]
