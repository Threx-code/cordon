"""Comparing a shipped bill of materials against what is actually there.

An SBOM is a claim: these are the components this artefact contains. Nothing in
the format makes the claim true, and a stale or curated one is worse than none,
because it is read as an inventory by everything downstream -- vulnerability
matching, licence review, incident response asking "were we exposed".

The comparison this makes is deliberately one-directional. It reports components
the scan resolved that the SBOM does not list, and stays quiet about the
reverse.

That asymmetry is the whole design. An SBOM listing something the scan did not
find is ordinary: the document may cover artefacts from another build stage,
another platform's wheels, or a runtime dependency that no lockfile in this
repository pins. An SBOM *missing* something the lockfile pins is different --
it means the document does not describe the thing that will be installed, and
every consumer treating it as an inventory is reasoning about the wrong set.

**Format handling is deliberately shallow.** CycloneDX and SPDX are large
specifications and this reads two fields from each: the component name and,
where present, its package URL. A full parser would be a dependency, a
maintenance burden, and no more accurate for this one question -- and a partial
parser that silently misread a document would produce exactly the confident
wrongness the check exists to catch. A document this cannot read is reported as
unread rather than treated as empty, because an empty SBOM and an unparsed one
would otherwise produce the same, very loud, result.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

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
from cordon_scanner.core.paths import basename
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit

SBOM_NAMES = (
    "bom.json",
    "sbom.json",
    "cyclonedx.json",
    "spdx.json",
)

SBOM_SUFFIXES = (
    ".cdx.json",
    ".spdx.json",
    ".sbom.json",
)

MAX_REPORTED = 10
"""How many missing components to name in one finding.

The count is the signal; the names are there so somebody can start looking. A
document that omits four hundred components has one problem, not four hundred,
and listing them all produces a finding nobody reads."""


class SbomDetector(BaseDetector):
    """Checks a committed bill of materials against the resolved graph."""

    id = "sbom"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, dependencies=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.SBOM.DRIFT.001",
                title="Bill of materials omits resolved dependencies",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=SbomDetector.id,
                remediation=(
                    "Regenerate the document from the lockfile as part of the "
                    "build. An inventory maintained by hand describes what "
                    "somebody remembered, not what ships."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.SBOM.UNREADABLE.001",
                title="Bill of materials could not be read",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=SbomDetector.id,
                remediation=(
                    "Check the document is valid CycloneDX or SPDX JSON. An "
                    "unreadable inventory is not an empty one."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit) or not ctx.dependencies:
            return ()

        content = unit.content
        if content.is_binary or not self.looks_like_sbom(content.path):
            return ()

        try:
            listed = self.components(content.text)
        except ValueError as exc:
            return [
                self._finding(
                    "OPERATIONAL.SBOM.UNREADABLE.001",
                    unit,
                    ctx,
                    f"{content.path} could not be parsed as CycloneDX or SPDX JSON: {exc}",
                )
            ]

        if not listed:
            # A document with no components is either empty or in a shape this
            # does not read. Either way, comparing against it would report every
            # dependency in the project as missing, which is a loud way of
            # saying nothing.
            return [
                self._finding(
                    "OPERATIONAL.SBOM.UNREADABLE.001",
                    unit,
                    ctx,
                    (
                        f"{content.path} lists no components in a shape this "
                        f"recognises, so nothing was compared against it"
                    ),
                )
            ]

        missing = sorted(
            {
                dependency.name
                for dependency in ctx.dependencies
                if dependency.name.lower() not in listed
                and (dependency.purl.split("@")[0].lower() not in listed)
            }
        )
        if not missing:
            return ()

        shown = ", ".join(missing[:MAX_REPORTED])
        more = f" and {len(missing) - MAX_REPORTED} more" if len(missing) > MAX_REPORTED else ""
        return [
            self._finding(
                "SUSPECT.SBOM.DRIFT.001",
                unit,
                ctx,
                (
                    f"{content.path} does not list {len(missing)} component(s) that this "
                    f"project resolves: {shown}{more}. Anything reading it as an "
                    f"inventory is reasoning about a different set of code."
                ),
            )
        ]

    @staticmethod
    def looks_like_sbom(path: str) -> bool:
        name = basename(path).lower()
        return name in SBOM_NAMES or name.endswith(SBOM_SUFFIXES)

    @staticmethod
    def components(text: str) -> set[str]:
        """Component identities named by the document, lowercased.

        Both names and package URLs are collected, because the two formats
        disagree about which is authoritative and a comparison that insisted on
        one would report drift wherever a document used the other.
        """
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise ValueError(str(exc)) from exc

        if not isinstance(document, dict):
            raise ValueError("the document is not a JSON object")

        found: set[str] = set()

        # CycloneDX: a `components` array of objects with `name` and `purl`.
        for entry in _sequence(document.get("components")):
            _collect(entry, found, ("name", "purl"))

        # SPDX: a `packages` array with `name` and external references that
        # carry the purl.
        for entry in _sequence(document.get("packages")):
            _collect(entry, found, ("name",))
            for reference in _sequence(entry.get("externalRefs")):
                locator = reference.get("referenceLocator") if isinstance(reference, dict) else None
                if isinstance(locator, str) and locator:
                    found.add(locator.split("@")[0].lower())

        return found

    def _finding(self, rule_id: str, unit: FileUnit, ctx: ScanContext, detail: str) -> Finding:
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        content: FileContent = unit.content
        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=content.path, line=1, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.raw[:4096]),
                redaction=RedactionMode.HASH_ONLY,
            ),
            remediation=declared.remediation,
            explanation=Explanation(summary=detail, matched_rule=rule_id),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=self.id,
            always_report=declared.category is Category.OPERATIONAL,
        )


def _sequence(value: Any) -> list[dict[str, Any]]:
    """The list of objects at a key, or nothing.

    An SBOM is written by whoever built the artefact, which for a dependency is
    not somebody this tool trusts. A field documented as an array arrives as
    whatever they put there.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _collect(entry: dict[str, Any], into: set[str], keys: tuple[str, ...]) -> None:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value:
            into.add(value.split("@")[0].lower())


__all__ = ["MAX_REPORTED", "SbomDetector"]
