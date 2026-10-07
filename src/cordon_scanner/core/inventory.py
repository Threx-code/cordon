"""The shared dependency record: one schema for every ecosystem, and what each check concluded.

A dependency in the report carries the same keys whatever ecosystem it came from -- namespace,
declared constraint, resolved version and how it was resolved, source, integrity, the path it
arrived by, its platform conditions, where it was declared and resolved -- and one status per
check. The statuses are the point of this module.

"No vulnerability found" and "the vulnerability check did not run" are different answers, and a
single `vulnerable: false` cannot tell them apart. So every check answers in words:

```
  advisory_status    vulnerable | no_matching_advisory | unavailable_feed | skipped |
                     not_applicable | error
  malware_status     malicious | suspicious | no_known_malicious_release | unavailable_feed |
                     skipped | not_applicable | error
  integrity_status   verified | mismatched | recorded | unavailable | not_applicable
  provenance_status  verified | invalid | absent | unsupported | not_checked
  licence_status     identified | conflicting | unknown | policy_violation | not_applicable
```

`not_applicable` throughout is a platform requirement (`python >=3.10`, Composer's `php`): in
the inventory, and not a package any package check is about.

`recorded` is a hash the lockfile carries and nothing has compared against the registry yet
(offline): present, not verified. `skipped` always says why in the resolution reason or the
scan's operational findings; it is never a silent pass.

Statuses are derived after every detector has run, from the findings each produced and from the
positive results detectors write into a `CheckLog` (a hash that matched, provenance that
verified), which no finding records because nothing was wrong.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Final

from cordon_scanner.core.models import Category, Dependency, Scope

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon_scanner.core.models import Finding
    from cordon_scanner.intel.advisories import AdvisoryDatabase

ARCHIVE_SUFFIXES: Final = (
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".zip",
    ".whl",
    ".gem",
    ".crate",
    ".nupkg",
    ".jar",
    ".war",
    ".aar",
)
GIT_PREFIXES: Final = (
    "git+",
    "git:",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "ssh://",
    "gist:",
)
PATH_PREFIXES: Final = ("file:", "link:", "portal:", "path:", "workspace:", "./", "../", "/", "~/")
_COMMIT: Final = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])"
)
_USERINFO: Final = re.compile(r"(?<=://)[^/@\s]{1,512}@")

#: Ecosystems whose registries publish verifiable build provenance Cordon checks (`--online`).
PROVENANCE_ECOSYSTEMS: Final = frozenset({"npm", "pypi"})
#: Where a dependency was found installed rather than declared: an image's packages.
INSTALLED_MARKERS: Final = frozenset({"installed-in-image"})
OS_ECOSYSTEMS: Final = frozenset({"deb", "apk", "rpm", "alpm", "ebuild"})
"""A distribution's packages, as their purl types name them (`images/packages.py` OsPackage)."""
OS_ADVISORY_ECOSYSTEMS: Final = frozenset({"deb", "apk", "rpm"})
"""The ones a distribution advisory source covers: Arch and Gentoo publish none Cordon reads."""
NAMED_BY_FILE: Final = "file-name"
"""`resolved_from` of a jar with no Maven metadata, named after its file: inventory, not a
coordinate any registry knows."""
RUNTIME_ECOSYSTEM: Final = "runtime"
"""A language runtime installed from its own release (`pkg:generic/node@22.23.3`): inventoried,
with no advisory source of its own -- Go's is matched as `stdlib`."""

LICENCE_POLICY_RULES: Final = frozenset(
    {
        "POLICY.LICENSE.COPYLEFT.001",
        "POLICY.LICENSE.WEAK_COPYLEFT.001",
        "POLICY.LICENSE.NETWORK_COPYLEFT.001",
        "POLICY.LICENSE.DENIED.001",
        "POLICY.LICENSE.NOT_ALLOWED.001",
        "POLICY.LICENSE.UNKNOWN.001",
    }
)
INTEGRITY_MISMATCH_RULES: Final = frozenset(
    {
        # The lockfile's hash is not among those the registry publishes for that version.
        "SUSPECT.PROVENANCE.MISMATCH.001",
        "SUSPECT.LOCKFILE.INTEGRITY_CONFLICT.001",
        "SUSPECT.LOCKFILE.INTEGRITY_MALFORMED.001",
    }
)
PROVENANCE_INVALID_RULES: Final = frozenset({"VULNERABLE.PROVENANCE.INVALID.001"})


class DependencyIdentity:
    """The namespace part of a package's identity, where its ecosystem has one."""

    @staticmethod
    def namespace(ecosystem: str, name: str) -> str | None:
        if not name:
            return None
        if ecosystem == "npm":
            return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None
        if ecosystem in ("maven", "gradle"):
            return name.split(":", 1)[0] if ":" in name else None
        if ecosystem == "composer":
            return name.split("/", 1)[0] if "/" in name else None
        if ecosystem in ("gomod", "swift", "nix"):
            return name.rsplit("/", 1)[0] if "/" in name else None
        if ecosystem == "actions":
            return name.split("/", 1)[0] if "/" in name else None
        if ecosystem in ("ansible", "vscode"):
            return name.split(".", 1)[0] if "." in name else None
        if ecosystem == "terraform":
            parts = name.split("/")
            return parts[-2] if len(parts) >= 2 else None
        if ecosystem == "image":
            return name.rsplit("/", 1)[0] if "/" in name else None
        if ecosystem == "homebrew":
            return name.rsplit("/", 1)[0] if name.count("/") >= 2 else None
        if ecosystem == "conda":
            return name.split("::", 1)[0] if "::" in name else None
        if ecosystem == "hex":
            return name.split("/", 1)[0] if "/" in name else None
        return None


class DependencySource:
    """Where a dependency comes from: `(source_type, source_url)`.

    `source_type` is one of `registry`, `git`, `path`, `archive`, `url`, `vendored`, `installed`.
    The URL is the one the lockfile or manifest records with any credentials removed: userinfo
    (`https://user:token@host`) and the whole query string, where tokens are passed.
    """

    @staticmethod
    def sanitise(url: str | None) -> str | None:
        if not url:
            return None
        cleaned = _USERINFO.sub("", url.strip())
        if "?" in cleaned:
            base, _, rest = cleaned.partition("?")
            fragment = rest.partition("#")[2]
            cleaned = base + (f"#{fragment}" if fragment else "")
        return cleaned or None

    @staticmethod
    def classify(dependency: Dependency) -> tuple[str, str | None]:
        if dependency.integrity in INSTALLED_MARKERS or dependency.ecosystem in OS_ECOSYSTEMS:
            return "installed", None
        if dependency.local:
            return "path", None
        if dependency.resolved_from and dependency.resolved_from.startswith("vendored:"):
            return "vendored", dependency.resolved_from[len("vendored:") :]
        reference = (dependency.resolved_from or "").strip()
        declared = (dependency.declared_spec or "").strip()
        for candidate in (reference, declared):
            kind = DependencySource._kind(dependency.ecosystem, candidate)
            if kind is not None:
                if candidate.lower().startswith("registry:"):
                    return kind, candidate
                return kind, DependencySource.sanitise(candidate) if kind != "path" else candidate
        return "registry", DependencySource.sanitise(reference) if "://" in reference else None

    @staticmethod
    def _kind(ecosystem: str, value: str) -> str | None:
        lowered = value.lower()
        if not lowered:
            return None
        if lowered.startswith("registry:"):
            return "registry"  # a named registry the project configures (Cargo, Composer, NuGet)
        if lowered.startswith(GIT_PREFIXES) or re.search(r"\.git(?:[#@/]|$)", lowered):
            return "git"
        if lowered.startswith(PATH_PREFIXES):
            return "path"
        if lowered.startswith(("http://", "https://", "oci://")):
            from cordon_scanner.ecosystems.registry import EcosystemRegistry

            implementation = EcosystemRegistry.get(ecosystem)
            if implementation is not None and implementation.is_registry_host(value):
                return "registry"
            path = lowered.partition("?")[0].partition("#")[0]
            # A code host's snapshot of a repository at a ref is that repository, not an
            # arbitrary download: `codeload.github.com/<owner>/<repo>/tar.gz/<commit>`,
            # `github.com/<owner>/<repo>/archive/<ref>.tar.gz`, GitLab's `/-/archive/`.
            if re.match(
                r"https?://codeload\.github\.com/[^/]+/[^/]+/(?:tar\.gz|zip|legacy\.tar\.gz)/", path
            ):
                return "git"
            if (
                re.match(r"https?://(?:www\.)?github\.com/[^/]+/[^/]+/archive/", path)
                or "/-/archive/" in path
            ):
                return "git"
            if path.endswith(ARCHIVE_SUFFIXES):
                return "archive"
            if re.match(
                r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)/[^/]+/[^/]+/?$",
                path,
            ):
                return "git"
            return "url"
        return None


class GitReference:
    """The ref a git source names: `URL@ref`, `URL#ref` (npm, Cargo), never a pip fragment."""

    TAG: Final = re.compile(r"v?\d{1,9}(?:\.\d{1,9}){1,6}(?:[-+][0-9A-Za-z.\-]{1,64})?")

    @staticmethod
    def ref(spec: str) -> str | None:
        text = spec.strip().removeprefix("git+")
        text, _, fragment = text.partition("#")
        if fragment and "=" not in fragment:
            return fragment or None
        body = text.split("://", 1)[1] if "://" in text else text
        before, at, after = body.rpartition("@")
        # The `@` of a ref follows the repository path; the one in `git@host:` is the user's.
        if at and "/" in before and after:
            return after
        return None


class DependencyResolution:
    """Whether a dependency's version is decided, and why: `(status, reason)`.

    `resolved`: an exact version from a lockfile, an exact pin, or an immutable commit.
    `partially_resolved`: a version is known but what installs can still move (a git branch or
    tag, which a push re-points). `unresolved`: a range, or nothing, with nothing to resolve it.
    """

    @staticmethod
    def status(dependency: Dependency) -> tuple[str, str]:
        if dependency.local:
            return "resolved", "the project's own code, read as source"
        if dependency.scope is Scope.PLATFORM:
            return (
                "unresolved",
                "a platform requirement, met by the environment rather than resolved",
            )
        if dependency.resolved_by and dependency.version:
            return "resolved", f"pinned by {dependency.resolved_by}"
        source, _ = DependencySource.classify(dependency)
        if source == "installed":
            return "resolved", "the version installed in the scanned image"
        if dependency.resolution_note and not dependency.version:
            return "unresolved", dependency.resolution_note
        reference = " ".join(
            filter(None, (dependency.resolved_from, dependency.declared_spec, dependency.version))
        )
        if source == "git":
            if _COMMIT.search(reference.lower()):
                return "resolved", "pinned to a commit"
            ref = GitReference.ref(dependency.resolved_from or dependency.declared_spec or "")
            if ref and GitReference.TAG.fullmatch(ref):
                return "partially_resolved", f"the tag {ref!r}, which can be re-pointed"
            if dependency.version:
                return "partially_resolved", "a git branch or tag, which can be re-pointed"
            if ref:
                return "unresolved", f"the branch or tag {ref!r}: a push can move either"
            if dependency.resolution_note:
                return "unresolved", dependency.resolution_note
            return "unresolved", "a git dependency with no recorded commit"
        if source == "vendored":
            return "resolved", "vendored into the repository at this version"
        if dependency.ecosystem == "image":
            # A digest names exactly one image; a tag names whichever image was pushed under it last.
            if dependency.integrity:
                # An archive a Dockerfile ADDs is pinned by the checksum BuildKit verifies.
                return "resolved", "pinned by its checksum" if source in (
                    "archive",
                    "url",
                ) else "pinned by its digest"
            if dependency.version == "latest":
                return "partially_resolved", "the latest tag: whatever image was pushed last"
            if dependency.version:
                return (
                    "partially_resolved",
                    "a tag, which the registry can re-point to another image",
                )
            return "unresolved", "no tag or digest"
        if (
            dependency.version
            and dependency.ecosystem in ("maven", "gradle")
            and dependency.version.upper().endswith("-SNAPSHOT")
        ):
            # A SNAPSHOT is re-published in place: the same version names whatever was deployed last.
            return "partially_resolved", "a SNAPSHOT version, which is re-published in place"
        if dependency.version:
            from cordon_scanner.ecosystems.registry import EcosystemRegistry

            if dependency.declared_in and EcosystemRegistry.lockfile_ecosystem(
                dependency.declared_in
            ):
                return "resolved", "resolved by the lockfile"
            declared = (dependency.declared_spec or "").strip()
            if dependency.ecosystem == "nuget" and declared and not declared.startswith("["):
                # `Version="1.2.3"` means at least 1.2.3, and NuGet restores the lowest version a
                # direct reference admits.
                return "resolved", "NuGet restores the lowest version the reference admits"
            return "resolved", "an exact pin in the manifest"
        if source in ("archive", "url"):
            return "unresolved", "a download URL with no recorded version"
        spec = (dependency.declared_spec or "").strip()
        if spec:
            return "unresolved", f"the range {spec!r} has no lockfile to resolve it"
        return "unresolved", "no version constraint and no lockfile"


class CheckLog:
    """Positive check results, written by detectors as they run: `(purl, check) -> status`.

    Findings record what went wrong. A registry hash that matched or a provenance bundle that
    verified produces no finding, so without this the record could only ever say `recorded`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._results: dict[tuple[str, str], str] = {}

    def record(self, purl: str, check: str, status: str) -> None:
        with self._lock:
            self._results[(purl, check)] = status

    def get(self, purl: str, check: str) -> str | None:
        with self._lock:
            return self._results.get((purl, check))

    def __len__(self) -> int:
        return len(self._results)

    # A context can cross into a worker process; the lock cannot, and is recreated there.
    def __getstate__(self) -> dict[tuple[str, str], str]:
        with self._lock:
            return dict(self._results)

    def __setstate__(self, state: dict[tuple[str, str], str]) -> None:
        self._lock = threading.Lock()
        self._results = dict(state)


@dataclass(frozen=True)
class InventoryContext:
    """What the statuses are judged against."""

    advisory_database: AdvisoryDatabase | None
    """The database the advisory detector used, or None when that detector did not run."""
    advisory_failed: bool = False
    offline: bool = True
    checks: CheckLog = field(default_factory=CheckLog)
    texts: Mapping[str, str] = field(default_factory=dict)
    """File text by path, for the line a dependency is declared or resolved on."""


class DependencyRecords:
    """Annotate the scan's dependencies with their record fields and check statuses."""

    @staticmethod
    def annotate(
        dependencies: Iterable[Dependency], findings: Iterable[Finding], context: InventoryContext
    ) -> tuple[Dependency, ...]:
        deps = tuple(dependencies)
        by_package: dict[str, list[Finding]] = {}
        for finding in findings:
            package = finding.location.package
            if package:
                by_package.setdefault(package, []).append(finding)
        paths = DependencyRecords._paths(deps)
        lines = _LineIndex(context.texts)
        out = []
        for dependency in deps:
            own = by_package.get(dependency.purl, [])
            if dependency.scope is Scope.PLATFORM:
                # A requirement on the platform (`python >=3.10`, `php ^8.1`): not a package, so
                # no package check applies to it, and it says so rather than "not checked".
                out.append(
                    replace(
                        dependency,
                        dependency_path=(dependency.name,),
                        manifest_line=dependency.manifest_line
                        or lines.find(dependency.manifest_path, dependency.name),
                        advisory_status="not_applicable",
                        malware_status="not_applicable",
                        integrity_status="not_applicable",
                        provenance_status="unsupported",
                        licence_status="not_applicable",
                    )
                )
                continue
            out.append(
                replace(
                    dependency,
                    # A chain worked out over a graph spread across files (Engine) stands.
                    dependency_path=dependency.dependency_path
                    or paths.get(id(dependency), (dependency.name,)),
                    manifest_line=dependency.manifest_line
                    or lines.find(dependency.manifest_path, dependency.name),
                    lockfile_line=dependency.lockfile_line
                    or lines.find(dependency.declared_in, dependency.name),
                    advisory_status=DependencyRecords._advisory(dependency, own, context),
                    malware_status=DependencyRecords._malware(dependency, own, context),
                    integrity_status=DependencyRecords._integrity(dependency, own, context),
                    provenance_status=DependencyRecords._provenance(dependency, own, context),
                    licence_status=DependencyRecords._licence(dependency, own),
                    finding_ids=tuple(sorted({f.fingerprint for f in own if f.fingerprint})),
                )
            )
        return tuple(out)

    # -- the statuses ------------------------------------------------------------------------

    @staticmethod
    def _advisory(dependency: Dependency, own: list[Finding], context: InventoryContext) -> str:
        if any(
            f.category is Category.VULNERABLE and f.rule_id not in PROVENANCE_INVALID_RULES
            for f in own
        ):
            return "vulnerable"
        if dependency.local:
            return "not_applicable"
        database = context.advisory_database
        if database is None:
            return "skipped"
        if context.advisory_failed:
            return "error"
        if dependency.ecosystem in OS_ECOSYSTEMS:
            if dependency.ecosystem not in OS_ADVISORY_ECOSYSTEMS:
                return "unavailable_feed"
            return "no_matching_advisory" if dependency.version else "skipped"
        if dependency.ecosystem == RUNTIME_ECOSYSTEM:
            return "unavailable_feed"
        if dependency.ecosystem == "image" and not database.covers("image"):
            # An image's vulnerabilities are its packages', reported by scanning the image.
            return "not_applicable"
        if not database.covers(dependency.ecosystem):
            return "unavailable_feed"
        if not dependency.version:
            return "skipped"
        return "no_matching_advisory"

    @staticmethod
    def _malware(dependency: Dependency, own: list[Finding], context: InventoryContext) -> str:
        if any(f.category is Category.MALICIOUS for f in own):
            return "malicious"
        if dependency.local:
            return "not_applicable"
        if any(f.category is Category.SUSPICIOUS and not f.is_suppressed for f in own):
            return "suspicious"
        database = context.advisory_database
        if database is None:
            return "skipped"
        if context.advisory_failed:
            return "error"
        if dependency.ecosystem in OS_ECOSYSTEMS or dependency.ecosystem == RUNTIME_ECOSYSTEM:
            return "not_applicable"
        if not database.covers(dependency.ecosystem):
            return "unavailable_feed"
        return "no_known_malicious_release"

    @staticmethod
    def _integrity(dependency: Dependency, own: list[Finding], context: InventoryContext) -> str:
        logged = context.checks.get(dependency.purl, "integrity")
        if (
            logged == "mismatched"
            or any(f.rule_id in INTEGRITY_MISMATCH_RULES for f in own)
            or (dependency.integrity or "").startswith("malformed:")
        ):
            return "mismatched"
        if logged == "verified":
            return "verified"
        if dependency.local or dependency.bundled:
            return "not_applicable"
        if dependency.integrity in INSTALLED_MARKERS:
            return "not_applicable"
        if dependency.ecosystem == "gomod" and dependency.name == "stdlib":
            return "not_applicable"  # arrives with the Go toolchain, not from the module proxy
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        implementation = EcosystemRegistry.get(dependency.ecosystem)
        if dependency.integrity:
            return "recorded"
        if (
            implementation is not None
            and not getattr(implementation, "records_integrity", True)
            # Maven and Gradle can record hashes, in a file of their own (`.mvn/checksums/`,
            # `verification-metadata.xml`): without it the hash is unavailable, not inapplicable.
            and not getattr(implementation, "integrity_companion", False)
        ):
            return "not_applicable"
        return "unavailable"

    @staticmethod
    def _provenance(dependency: Dependency, own: list[Finding], context: InventoryContext) -> str:
        logged = context.checks.get(dependency.purl, "provenance")
        if logged in ("verified", "invalid", "absent"):
            return logged
        if any(f.rule_id in PROVENANCE_INVALID_RULES for f in own):
            return "invalid"
        # POLICY.PROVENANCE.UNVERIFIED: an attestation exists and could not be checked -- not
        # absent, not verified: `not_checked`, with that finding saying why.
        if dependency.ecosystem not in PROVENANCE_ECOSYSTEMS or dependency.local:
            return "unsupported"
        return "not_checked"

    @staticmethod
    def _licence(dependency: Dependency, own: list[Finding]) -> str:
        if any(f.rule_id in LICENCE_POLICY_RULES and not f.is_suppressed for f in own):
            return "policy_violation"
        if not dependency.license:
            return "unknown"
        from cordon_scanner.intel.licenses import LicenseCategory, LicenseClassifier

        declared = [p for p in re.split(r"\s*;\s*", dependency.license) if p]
        categories = {LicenseClassifier.classify(p) for p in declared}
        if LicenseCategory.UNKNOWN in categories:
            return "unknown"
        if len(categories) > 1:
            return "conflicting"
        return "identified"

    # -- the path a dependency arrived by -----------------------------------------------------

    @staticmethod
    def _paths(deps: tuple[Dependency, ...]) -> dict[int, tuple[str, ...]]:
        """One chain from a direct dependency to each one, within its own lockfile."""
        groups: dict[tuple[str | None, str], dict[str, Dependency]] = {}
        for dependency in deps:
            groups.setdefault((dependency.declared_in, dependency.ecosystem), {}).setdefault(
                dependency.name, dependency
            )
        out: dict[int, tuple[str, ...]] = {}
        for dependency in deps:
            group = groups.get((dependency.declared_in, dependency.ecosystem), {})
            chain = [dependency.name]
            current = dependency
            seen = {dependency.name}
            while not current.direct and current.parents and len(chain) < 64:
                candidates = [group[p] for p in current.parents if p in group and p not in seen]
                if not candidates:
                    break
                current = min(candidates, key=lambda d: (d.depth, d.name))
                seen.add(current.name)
                chain.append(current.name)
            out[id(dependency)] = tuple(reversed(chain))
        return out


class _LineIndex:
    """The first line of a file that names a dependency, computed once per file."""

    def __init__(self, texts: Mapping[str, str]) -> None:
        self._texts = texts
        self._lines: dict[str, list[str]] = {}

    def find(self, path: str | None, name: str) -> int | None:
        if not path or not name or path not in self._texts:
            return None
        lines = self._lines.get(path)
        if lines is None:
            lines = self._texts[path].splitlines()
            self._lines[path] = lines
        pattern = re.compile(r"(?<![\w@./-])" + re.escape(name) + r"(?![\w-])")
        for number, line in enumerate(lines[:200_000], start=1):
            if name in line and pattern.search(line):
                return number
        return None


__all__ = [
    "PROVENANCE_ECOSYSTEMS",
    "CheckLog",
    "DependencyIdentity",
    "DependencyRecords",
    "DependencyResolution",
    "DependencySource",
    "InventoryContext",
]
