"""What a package's own history says about the scanned release: the releases and maintainers before it,
how it is distributed, the facts the registry gives, a young dependency the release introduced,
and the ceiling an established release earns.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.engine.package_format import PackageFormat
from cordon_scanner.engine.pipeline.constants import YOUNG_DEPENDENCY_RULE
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence


class History:
    """A package's release history, as evidence about the scanned release."""

    @staticmethod
    def registry_facts(units: Sequence[FileUnit], root: Path | None = None) -> dict[str, float]:
        """What the registry recorded about this release, as verdict facts (`reg_*`).

        Read from the store `cordon-scanner intel acquire` wrote (`intel/registry_record.py`);
        nothing acquired, nothing added -- and `reg_known` absent tells the verdict so. These are
        second-review facts: the trainer keeps them out of the content-only measure.
        """
        from cordon_scanner.intel.registry import ECOSYSTEMS, RegistryRecord

        files = [u for u in units if isinstance(u, FileUnit)]
        distribution = History.history_distribution(files)
        if distribution not in ECOSYSTEMS:
            return {}
        identity = History.history_identity(files, distribution)
        if identity is None:
            return {}
        record = RegistryRecord.load(*identity, root=root)
        return record.facts() if record is not None else {}

    @staticmethod
    def history_identity(
        units: Sequence[FileUnit], distribution: str
    ) -> tuple[str, str, str] | None:
        """(ecosystem, name, version) of the release a published archive is, for
        `ReleaseHistory`: the manifest its format names, read the way that format writes it."""
        if RegistryFacts.identity_in_metadata(distribution):
            identities, _ = ReleaseChecks.release_identities(units)
            for ecosystem, name, version, _ in identities:
                if ecosystem == distribution:
                    return ecosystem, name, version
            return None
        if distribution == "openvsx":
            manifest = next((u for u in units if u.path.endswith("!extension/package.json")), None)
            try:
                document = (
                    ScannedJson.loads(manifest.content.text) if manifest is not None else None
                )
            except (ValueError, RecursionError):
                return None
            if not isinstance(document, dict):
                return None
            publisher, extension, release = (
                document.get("publisher"),
                document.get("name"),
                document.get("version"),
            )
            if all(isinstance(v, str) and v for v in (publisher, extension, release)):
                # As published: the API redirects any other spelling to this one.
                return "openvsx", f"{publisher}.{extension}", str(release)
            return None
        pattern = RegistryFacts.release_manifest(distribution)
        if pattern is None:
            return None
        for unit in units:
            found = pattern.search(unit.path)
            if not found:
                continue
            text = unit.content.text[:20000]
            if unit.path.endswith(".gz"):
                # A gem's `metadata.gz`: the gemspec as YAML, gzipped, read bounded.
                import gzip
                import zlib

                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                        text = stream.read(20000).decode("utf-8", "replace")
                except (OSError, EOFError, zlib.error):
                    continue
            identity = RegistryFacts.release_identity(distribution, unit.path, text, found)
            if identity is not None:
                return distribution, *identity
        return None

    @staticmethod
    def young_dependency_introduced(
        units: list[FileUnit],
        distribution: str,
        ctx: ScanContext,
        root: Path | None = None,
    ) -> list[Finding]:
        """A dependency this release adds over its established release that was itself first
        published only days before this release.

        Read from the store `cordon-scanner intel acquire` wrote; nothing acquired, nothing reported. An
        established package's compromised release pulls in a name created for the attack -- the
        `@mastra/*` releases of 2026-06-17 added `easy-day-js` -- while a dependency the
        package's own scope publishes (a monorepo's new sibling) is the maintainers' and is not
        counted.
        """
        from datetime import datetime, timedelta

        from cordon_scanner.intel.registry import YOUNG_DEPENDENCY_DAYS, ReleaseHistory

        identity = History.history_identity(units, distribution)
        if identity is None:
            return []
        baseline = ReleaseHistory.load(*identity, root=root)
        if baseline is None or not baseline.baseline_version or not baseline.published:
            return []
        try:
            released = datetime.fromisoformat(baseline.published)
        except ValueError:
            return []
        scope = identity[1].split("/", 1)[0] + "/" if identity[1].startswith("@") else None
        manifest = next(
            (
                u.path
                for u in units
                if u.path.endswith(("!package/package.json", "/PKG-INFO", ".dist-info/METADATA"))
            ),
            units[0].path if units else "",
        )
        out: list[Finding] = []
        family = re.sub(r"^@[^/]+/", "", identity[1]).lower()
        for dependency, first in sorted(baseline.introduced.items()):
            if not first or (scope and dependency.startswith(scope)):
                continue
            bare = re.sub(r"^@[^/]+/", "", dependency).lower()
            stem = min(family, bare, key=len)
            if len(stem) >= 4 and (
                bare.startswith(family) or family.startswith(bare.split("-")[0])
            ):
                # A package split into siblings: `astn` adds `astn-runtime` the day it is created.
                continue
            try:
                appeared = datetime.fromisoformat(first)
            except ValueError:
                continue
            if not timedelta(0) <= released - appeared <= timedelta(days=YOUNG_DEPENDENCY_DAYS):
                continue
            days = (released - appeared).days
            out.append(
                replace(
                    OperationalFinding.build(
                        path=manifest,
                        rule_id=YOUNG_DEPENDENCY_RULE,
                        message=(
                            f"{identity[1]} {identity[2]} adds the dependency {dependency}, which "
                            f"its established release {baseline.baseline_version} did not have and "
                            f"which was first published {days} day(s) before this release. A "
                            "compromised release of an established package pulls in a name "
                            "created for the attack."
                        ),
                        remediation=(
                            f"Read {dependency} before installing this release; pin the previous "
                            "release until its maintainers confirm the change."
                        ),
                        # A warning: maintainers add new packages of their own too (review 98:
                        # 6 of 2,481 random npm and PyPI releases), so the name alone does not
                        # block; what the new dependency's own code does is the decision.
                        category=Category.SUSPICIOUS,
                        severity=Severity.MEDIUM,
                    ),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(Severity.MEDIUM, Confidence.MEDIUM),
                    detector="release-history",
                )
            )
        return out

    @staticmethod
    def established_release_ceiling(
        findings: list[Finding],
        units: list[FileUnit],
        distribution: str,
        root: Path | None = None,
        hook_paths: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        """Suspicious findings in files this package has shipped unchanged since an established
        release, reported below the gate.

        `intel/release_history.py` holds, for a release acquired beforehand (`cordon intel
        acquire`), the per-file hashes of the newest release published at least
        `release_history.MIN_AGE_DAYS` earlier. A finding in a file byte-identical to that
        release describes code the ecosystem has carried for months; one in a file that is new
        or changed in this release keeps its grade, and that is where a compromised release puts
        its payload. Nothing acquired, nothing changed: this reads a file, never the network. A
        MALICIOUS finding is never lowered.
        """
        from cordon_scanner.intel.registry import ReleaseHistory

        identity = History.history_identity(units, distribution)
        if identity is None:
            return findings
        baseline = ReleaseHistory.load(*identity, root=root)
        if baseline is None or not baseline.baseline_version:
            return findings
        digests = {unit.path: hashlib.sha256(unit.content.raw).hexdigest() for unit in units}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id == "SUSPECT.OBFUSCATION.PACKED.001"
                and finding.severity > Severity.MEDIUM
                and path in digests
                and path not in hook_paths
                and ReleaseHistory.key(path, identity[2]) in baseline.obfuscated
            ):
                # Obfuscated output changes on every build, so it is never byte-identical; what
                # the established release shows is that this file was already obfuscated months
                # ago. A new package, or a readable file turned obfuscated in this release --
                # the shape of a compromised release -- keeps its grade, as does anything an
                # install hook runs.
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + f" The same file was already obfuscated in {baseline.baseline_version}, "
                    f"published {(baseline.baseline_published or '')[:10]}, at least 90 days "
                    "before this release, so it is reported below the gate.",
                )
            elif (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path in digests
                and baseline.unchanged(ReleaseHistory.key(path, identity[2]), digests[path])
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + f" This file is byte-identical in {baseline.baseline_version}, published "
                    f"{(baseline.baseline_published or '')[:10]}, at least "
                    "90 days before this release, so it is reported below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def history_distribution(units: list[FileUnit]) -> str:
        """The format release history knows this archive as: a published package's, or Open VSX
        for an editor extension (`.vsix`), which is not otherwise graded as a package."""
        package = PackageFormat.of(units)
        if package:
            return package
        tops = {u.path.partition("!")[2] for u in units if u.path.count("!") == 1}
        if "extension.vsixmanifest" in tops and "extension/package.json" in tops:
            return "openvsx"
        return ""


__all__ = ["History"]
