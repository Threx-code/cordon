"""The inventory a scan reports: each dependency annotated with what every check concluded.

The schema and the statuses are `foundation.dependencies`' (where every layer can read them); this
is the engine's part, which derives each status after the detectors have run, from their findings,
the `CheckLog` they wrote and the intelligence the scan consulted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.foundation.models import Category, Scope
from cordon_scanner.foundation.results import Dependency

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.intel.base import Advisories

from cordon_scanner.foundation.dependencies import (
    INSTALLED_MARKERS,
    INTEGRITY_MISMATCH_RULES,
    LICENCE_POLICY_RULES,
    OS_ADVISORY_ECOSYSTEMS,
    OS_ECOSYSTEMS,
    PROVENANCE_ECOSYSTEMS,
    PROVENANCE_INVALID_RULES,
    RUNTIME_ECOSYSTEM,
    CheckLog,
)


@dataclass(frozen=True)
class InventoryContext:
    """What the statuses are judged against."""

    advisory_database: Advisories | None
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
        lines = _LineIndex(
            context.texts,
            [(d.manifest_path, d.name) for d in deps] + [(d.declared_in, d.name) for d in deps],
        )
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
        if RegistryFacts.is_builtin(dependency.ecosystem, dependency.name):
            return "not_applicable"  # arrives with the toolchain (Go's stdlib), not from a registry
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
        from cordon_scanner.intel.registry import LICENSE_UNKNOWN, LicenseClassifier

        declared = [p for p in re.split(r"\s*;\s*", dependency.license) if p]
        categories = {LicenseClassifier.classify(p) for p in declared}
        if LICENSE_UNKNOWN in categories:
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
    r"""The first line of a file that names a dependency.

    A name is found where `(?<![\w@./-])NAME(?![\w-])` matches. The lookbehind starts every
    match at the start of a maximal run of `[\w@./-]`, and the lookahead ends it at the run's end
    or just before an `@`, `.` or `/` inside it, so the names a line holds are exactly those
    prefixes of its runs. The caller says up front which names it will ask of which file (the
    dependencies parsed from it); on a file's first lookup one pass over its lines records the
    first line of each of those, and every lookup after is a dictionary read. Searching the file
    again for each dependency made a lockfile's cost grow with the square of its entries. Memory
    is what was asked for, never what the file holds. A name with another character (a space, a
    `:`), or one not asked for up front, is searched for line by line as before."""

    #: Lines read, as the line-by-line search reads them.
    MAX_LINES: ClassVar[int] = 200_000
    RUN: ClassVar[re.Pattern[str]] = re.compile(r"[\w@./-]+")
    INNER_END: ClassVar[re.Pattern[str]] = re.compile(r"[@./]")

    def __init__(
        self, texts: Mapping[str, str], queries: Iterable[tuple[str | None, str]] = ()
    ) -> None:
        self._texts = texts
        self._lines: dict[str, list[str]] = {}
        self._wanted: dict[str, set[str]] = {}
        for path, name in queries:
            if path and name and _LineIndex.RUN.fullmatch(name):
                self._wanted.setdefault(path, set()).add(name)
        self._first: dict[str, dict[str, int]] = {}

    def find(self, path: str | None, name: str) -> int | None:
        if not path or not name or path not in self._texts:
            return None
        lines = self._lines.get(path)
        if lines is None:
            lines = self._texts[path].splitlines()
            self._lines[path] = lines
        wanted = self._wanted.get(path)
        if wanted is not None and name in wanted:
            if path not in self._first:
                self._first[path] = _LineIndex.first_lines(lines, wanted)
            return self._first[path].get(name)
        return _LineIndex.search(lines, name)

    @staticmethod
    def first_lines(lines: list[str], wanted: set[str]) -> dict[str, int]:
        """The first line holding each wanted name, in one pass. A prefix longer than the longest
        wanted name cannot be one, so no run is cut past that length."""
        longest = max(len(name) for name in wanted)
        first: dict[str, int] = {}
        for number, line in enumerate(lines[: _LineIndex.MAX_LINES], start=1):
            for run in _LineIndex.RUN.finditer(line):
                text = run.group()
                for found in _LineIndex.INNER_END.finditer(text):
                    end = found.start()
                    if end > longest:
                        break
                    if end and text[:end] in wanted:
                        first.setdefault(text[:end], number)
                if len(text) <= longest and text in wanted:
                    first.setdefault(text, number)
        return first

    @staticmethod
    def search(lines: list[str], name: str) -> int | None:
        """The first line that names `name`, read line by line."""
        pattern = re.compile(r"(?<![\w@./-])" + re.escape(name) + r"(?![\w-])")
        for number, line in enumerate(lines[: _LineIndex.MAX_LINES], start=1):
            if name in line and pattern.search(line):
                return number
        return None


__all__ = [
    "DependencyRecords",
    "InventoryContext",
]
