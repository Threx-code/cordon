"""A package whose payload is in a dependency it declares (review 98, class 2).

A delivery vehicle is a package with nothing to catch in its own files: it declares a dependency,
and the dependency carries the payload, so installing the vehicle installs the malware. Scanning the
vehicle alone can never see it. With a dependency source, each dependency the package declares for
install (npm's `dependencies` and `optionalDependencies`; in every other ecosystem, the runtime and
optional dependencies its own manifest declares) is resolved to the highest version its range accepts,
scanned with the same detectors, and when that scan calls the dependency's own content malicious
the vehicle is blocked too, naming the dependency:

```
   vehicle.tgz ── package.json declares ──► dep@range
                                              │ resolve: --dependency-store DIR (offline)
                                              │          or the registry (--online, sha512-checked)
                                              ▼
                                         scan dep.tgz ── malicious by its content? ──► MALWARE.DEPENDENCY.PAYLOAD.001
```

One level only: a dependency's own dependencies are not followed, and its known-malware intel and
policy findings do not count, so the rule measures content, never a label. A dependency that cannot
be resolved is skipped, never treated as clean or as malware.
"""

from __future__ import annotations

import functools
import json
import re
import tarfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.foundation.models import Category, Confidence, Scope, Severity

if TYPE_CHECKING:
    import argparse

    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.foundation.results import ScanResult

RULE_ID = "MALWARE.DEPENDENCY.PAYLOAD.001"
#: Declared with the manifest rules (`ManifestDetector`), as the release-comparison rules are.
DETECTOR = "manifest"
#: More than this many declared dependencies are not all resolved: a vehicle declares a handful.
MAX_DEPENDENCIES = 32
MAX_MANIFEST_BYTES = 1 << 20
#: Findings that describe something other than the dependency's own bytes.
NOT_CONTENT = ("SECRET.", "POLICY.", "VULNERABLE.", "OPERATIONAL.", "SUSPECT.RELEASE.", RULE_ID)


@dataclass(frozen=True)
class Resolved:
    name: str
    version: str
    path: Path


class EcosystemDependencies:
    """The same question for a package of any other ecosystem: its declared dependencies are what
    the scan read from its own manifest, each range is read in the ecosystem's own syntax
    (`VersionRanges`), and each release is fetched from the ecosystem's verified archive source."""

    #: The scopes an install of the package installs.
    INSTALLED: Final = frozenset({Scope.RUNTIME, Scope.OPTIONAL})

    @staticmethod
    def ecosystem_of(result: ScanResult) -> str | None:
        """The ecosystem of the package scanned: the one its own manifest's dependencies are in."""
        counts: dict[str, int] = {}
        for d in result.dependencies:
            if d.direct and "!" in (d.declared_in or ""):
                counts[d.ecosystem] = counts.get(d.ecosystem, 0) + 1
        return max(counts, key=lambda e: (counts[e], e)) if counts else None

    @classmethod
    def declared(cls, result: ScanResult, ecosystem: str) -> dict[str, str]:
        """`{name: range}` of what installing the package installs, from its own manifest."""
        out = {
            d.name: (d.declared_spec or "").strip()
            for d in result.dependencies
            if d.direct
            and d.ecosystem == ecosystem
            and d.scope in cls.INSTALLED
            and "!" in (d.declared_in or "")
            and not d.local
        }
        return dict(sorted(out.items())[:MAX_DEPENDENCIES])

    @staticmethod
    def admitted(ecosystem: str, spec: str, versions: list[str]) -> list[str]:
        """The versions an install resolves the declaration to: those its range admits, or, where
        the ecosystem resolves no range upward (`NO_RANGES`), the version the declaration names."""
        from cordon_scanner.intel.advisories.ranges import VersionRanges

        if ecosystem in VersionRanges.NO_RANGES:
            return [v for v in versions if v == spec.lstrip("=v ") or v == spec]
        if not spec:
            return list(versions)
        return [v for v in versions if VersionRanges.admits(ecosystem, spec, v)]

    @classmethod
    def resolve(
        cls, ecosystem: str, name: str, spec: str, store: Path | None, into: Path
    ) -> Resolved | None:
        """The highest release the declaration admits, from the store or the verified source."""
        from cordon_scanner.intel.advisories.versions import Versions

        held = cls._held(store, ecosystem).get(name, {}) if store else {}
        if store:
            versions = list(held)
        else:
            from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
            from cordon_scanner.intel.registries.registry_client import RegistryError

            try:
                versions = ArchiveSources.versions(ecosystem, name)
            except (RegistryError, OSError, ValueError):
                return None
        accepted = cls.admitted(ecosystem, spec, versions)
        if not accepted:
            return None
        version = max(accepted, key=lambda v: Versions.sort_key(ecosystem, v))
        if store:
            return Resolved(name, version, held[version])
        return cls._fetched(ecosystem, name, version, into)

    @staticmethod
    def _fetched(ecosystem: str, name: str, version: str, into: Path) -> Resolved | None:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
        from cordon_scanner.intel.registries.registry_client import RegistryError
        from cordon_scanner.sources.package import PackageTarget

        try:
            archive = ArchiveSources.package_archive(ecosystem, name, version)
        except (RegistryError, OSError, ValueError):
            return None
        path = into / PackageTarget.safe_filename(archive.filename, ecosystem)
        path.write_bytes(archive.data)
        return Resolved(name, version, path)

    @staticmethod
    @functools.lru_cache(maxsize=8)
    def _held(store: Path, ecosystem: str) -> dict[str, dict[str, Path]]:
        """`{name: {version: path}}` of a store's `<ecosystem>/<name>@<version>.<suffix>` files (a
        `/` in a name written `_`), listed once."""
        held: dict[str, dict[str, Path]] = {}
        folder = store / ecosystem
        for path in folder.iterdir() if folder.is_dir() else ():
            stem = re.sub(r"\.(?:tar\.gz|tgz|crate|gem|whl|nupkg|zip|tar|jar)$", "", path.name)
            for name, version in EcosystemDependencies._splits(stem):
                for key in {name, name.replace("_", "/")}:
                    held.setdefault(key, {}).setdefault(version, path)
        return held

    @staticmethod
    def _splits(stem: str) -> list[tuple[str, str]]:
        """Every `(name, version)` a stored file's stem can be: split at an `@` or a `-` that starts
        a version (`a-b-1.0.0` is `a-b` at 1.0.0, never `a` at `b-1.0.0`)."""
        out = []
        start = 1 if stem.startswith("@") else 0
        for index in range(start, len(stem)):
            if stem[index] in "@-" and stem[index + 1 : index + 2].isdigit():
                out.append((stem[:index], stem[index + 1 :]))
        return out


class DependencyPayload:
    """Resolves and scans the dependencies one package archive declares: npm's read from its
    tarball, every other ecosystem's through `EcosystemDependencies`."""

    @staticmethod
    def add_argument(group: Any) -> None:
        group.add_argument(
            "--dependency-store",
            metavar="DIR",
            help=(
                "a directory of package archives (<ecosystem>/<name>@<version>.<suffix>, a / written _) to "
                "resolve the scanned package's declared dependencies from; each is scanned, and "
                "one whose own content is malicious blocks this package "
                "(MALWARE.DEPENDENCY.PAYLOAD.001). With --online the registry is asked instead"
            ),
        )

    @staticmethod
    def declared(target: Path) -> tuple[str, dict[str, str]]:
        """`(ecosystem, {name: range})` from an npm archive's own top-level package.json."""
        try:
            with tarfile.open(target) as archive:
                for entry in archive:
                    parts = entry.name.split("/")
                    if entry.isfile() and len(parts) == 2 and parts[1] == "package.json":
                        if entry.size > MAX_MANIFEST_BYTES:
                            return "npm", {}
                        handle = archive.extractfile(entry)
                        manifest = json.loads(handle.read() if handle else b"{}")
                        break
                else:
                    return "npm", {}
        except (OSError, tarfile.TarError, ValueError, UnicodeDecodeError):
            return "npm", {}
        out: dict[str, str] = {}
        for key in ("dependencies", "optionalDependencies"):
            section = manifest.get(key) if isinstance(manifest, dict) else None
            if isinstance(section, dict):
                out.update({str(n): str(r) for n, r in section.items() if isinstance(r, str)})
        if isinstance(manifest, dict) and manifest.get("name") in out:
            out.pop(str(manifest["name"]))
        return "npm", dict(sorted(out.items())[:MAX_DEPENDENCIES])

    @staticmethod
    def blocking(result: ScanResult, config: Any) -> list[Finding]:
        """The dependency's findings that call its own content malicious and trip the gate.

        Malicious only, never a suspicious heuristic: what a dependency's verdict does to the
        package declaring it, it does to every package that declares it. `vite` warns of an
        unexplained effect, and passing that on blocked a package of nothing but a tsconfig for
        depending on it (review 98); a suspicious finding stays the dependency's own to explain."""
        from cordon_scanner.decide.policy import PolicyGate

        return [
            f
            for f in result.findings
            if f.category is Category.MALICIOUS
            and PolicyGate._fails(f, config.policy)
            and not f.rule_id.startswith(NOT_CONTENT)
            and ".KNOWN" not in f.rule_id
        ]

    @staticmethod
    def finding(archive: str, dependency: Resolved, spec: str, cause: Finding) -> Finding:
        from cordon_scanner.foundation.results import OperationalFinding

        path = f"{archive}!package/package.json" if archive else "package.json"
        base = OperationalFinding.build(
            path=path,
            rule_id=RULE_ID,
            message=(
                f"Declares the dependency {dependency.name} ({spec!r}, resolved to "
                f"{dependency.version}), whose own content is malicious: {cause.rule_id} in "
                f"{cause.location.path.rpartition('!')[2]}. Installing this package installs it."
            ),
            remediation=(
                "Do not install this package. Its own files may be harmless; what it installs is not. "
                "Read the named dependency's finding before allowing either."
            ),
            category=Category.MALICIOUS,
            severity=Severity.CRITICAL,
        )
        return replace(base, confidence=Confidence.HIGH, always_report=False, detector=DETECTOR)

    @classmethod
    def applied(
        cls, args: argparse.Namespace, target: Path, result: ScanResult, config: Any, selected: Any
    ) -> ScanResult:
        """The scan result, plus a block for each declared dependency blocked by its content."""
        import tempfile

        from cordon_scanner import Scanner
        from cordon_scanner.intel.malware.feed import FeedClient

        store = getattr(args, "dependency_store", None)
        online = bool(args.online) and not args.offline and not FeedClient.offline_requested()
        if not target.is_file() or not (store or online):
            return result
        ecosystem = EcosystemDependencies.ecosystem_of(result)
        declared = EcosystemDependencies.declared(result, ecosystem) if ecosystem else {}
        if not declared and target.name.endswith((".tgz", ".tar.gz")):
            # A tarball whose scan recorded no manifest dependencies: read its package.json.
            ecosystem, declared = cls.declared(target)
        if not declared or not ecosystem:
            return result
        archive = next(
            (f.location.path.partition("!")[0] for f in result.findings if "!" in f.location.path),
            "",
        )
        added: list[Finding] = []
        unread: list[tuple[str, str]] = []
        with tempfile.TemporaryDirectory(prefix="cordon-deps-") as work:
            for name, spec in declared.items():
                try:
                    found = EcosystemDependencies.resolve(
                        ecosystem, name, spec, Path(store) if store else None, Path(work)
                    )
                except (OSError, ValueError, KeyError):
                    found = None
                if found is None:
                    continue
                scanned = Scanner(config, detectors=selected).scan(found.path)
                causes = cls.blocking(scanned, config)
                if causes:
                    added.append(cls.finding(archive, found, spec, causes[0]))
                else:
                    # Installing the vehicle installs the dependency: a part of it its own content
                    # left unread is this package's gap too, and blocks as the vehicle's would.
                    unread.extend(cls.unread(scanned, config, found))
        if not added and not unread:
            return result
        findings = (*result.findings, *added, *cls.gap_findings(unread))
        return replace(
            result,
            findings=tuple(sorted(findings, key=lambda f: -f.severity.value)),
            complete=result.complete and not unread,
            content_complete=result.content_complete and not unread,
            content_gaps=(*result.content_gaps, *unread),
        )

    @staticmethod
    def unread(scanned: ScanResult, config: Any, found: Resolved) -> list[tuple[str, str]]:
        """The content gaps of a dependency's scan no accepted gap covers, under the dependency's
        archive name, so the vehicle's report says which dependency and which file."""
        from cordon_scanner.decide.policy import PolicyGate

        name = found.path.name
        return [
            (rule, path if path.startswith(name) else f"{name}!{path}")
            for rule, path in PolicyGate._unaccepted_gaps(scanned, config.policy)
        ]

    @staticmethod
    def gap_findings(unread: list[tuple[str, str]]) -> list[Finding]:
        """One record per unread part of a dependency, so the gap is stated where it is reported."""
        from cordon_scanner.foundation.results import OperationalFinding

        return [
            OperationalFinding.build(
                path=path,
                rule_id=rule,
                message=(
                    "Part of a dependency this package declares, which installing the package "
                    "installs, was not examined, so the package cannot be called clean."
                ),
                remediation=(
                    "Find out why the dependency could not be read; accept the gap only in "
                    "policy.accepted_gaps."
                ),
                severity=Severity.MEDIUM,
            )
            for rule, path in unread
        ]
