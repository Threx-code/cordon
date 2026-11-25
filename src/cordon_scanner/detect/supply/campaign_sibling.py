"""A published package that is one campaign with releases already condemned, in any ecosystem.

A campaign republishes one payload under many names and versions. Its variants share what a
renaming does not touch -- the manifest's shape, the file tree, the dependency list -- and
`CampaignFingerprint` reduces a package to those three facets. The shipped `CampaignIndex` holds the
facets of releases already recorded as malicious; a package agreeing with one of them on two
informative facets is that campaign's next variant until a reviewer says otherwise:

    two facets shared with a condemned release  ->  SUSPECT.CAMPAIGN.SIBLING.001 (high, held)

Intel, not content: what it knows is what was condemned before, so it counts toward the
name/provenance bar and never toward content recall (`bench/tools/content.py`). Measured on the
study half, time-honest (only siblings condemned before each release): 147 of 1,923 npm malware
releases, 9 of them missed by every content rule; 0 of 5,085 benign npm packages held apart from the
reference set. The release itself, by name and version, is not its own sibling.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, Unit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
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
from cordon_scanner.intel.registry import CAMPAIGN_FACETS, CampaignFingerprint, CampaignIndex

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext

SIBLING_RULE = "SUSPECT.CAMPAIGN.SIBLING.001"
MAX_MANIFEST = 1 << 20


class CampaignSiblingDetector(BaseDetector):
    """Reports a published package, in any ecosystem, whose campaign fingerprint matches a condemned release's."""

    id = "campaign-sibling"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True, condemned=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=SIBLING_RULE,
                title="Package is a variant of a condemned campaign",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=CampaignSiblingDetector.id,
                message=(
                    "This package shares two of its manifest shape, file layout and dependency "
                    "list with a release already recorded as malicious, and neither shared value "
                    "is common among ordinary packages: the way one campaign republishes its "
                    "payload under new names and versions."
                ),
                remediation=(
                    "Do not install it until it is reviewed; compare it with the condemned release "
                    "the finding names."
                ),
                references=(references.OSV,),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        found = CampaignSiblingDetector.siblings_of(unit, ctx)
        if found is None or not found[1]:
            return ()
        return (self._finding(unit, ctx, *found),)

    @staticmethod
    def root_manifest(path: str) -> str | None:
        """The ecosystem whose package this archive member is the manifest of: a manifest file the ecosystem's own
        parser reads, at the package's root (at most one directory in) or where its archive keeps it."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        _, bang, member = path.rpartition("!")
        if not bang or member.count("/") > 1:
            return None
        ecosystem = EcosystemRegistry.manifest_ecosystem(member)
        if ecosystem in EcosystemRegistry.PACKAGE_JSON_FINGERPRINTS:
            # As the shipped index was built: the package.json one directory in, never a deno.json.
            return (
                ecosystem if member.count("/") == 1 and member.endswith("/package.json") else None
            )
        return ecosystem

    @staticmethod
    def siblings_of(
        unit: FileUnit, ctx: ScanContext
    ) -> tuple[dict[str, str | None], list[dict[str, Any]]] | None:
        """For a package's root manifest, in any ecosystem: its facets and the condemned releases sharing two of
        them, itself excluded; None for any other file. The `package` rule module reads the same answer
        (`modules.scanner_facts`)."""
        content = unit.content
        ecosystem = CampaignSiblingDetector.root_manifest(content.path)
        if ecosystem is None:
            return None
        if content.truncated or len(content.raw) > MAX_MANIFEST:
            return None
        archive = content.path.rpartition("!")[0]
        prefix = archive + "!"
        paths = [
            p[len(prefix) :]
            for p in ctx.tree_paths
            if p.startswith(prefix) and "!" not in p[len(prefix) :]
        ]
        facets = CampaignFingerprint.of_manifest(ecosystem, content, paths)
        own = CampaignSiblingDetector.identity(ecosystem, content)
        siblings = [
            r
            for r in CampaignIndex.shipped().siblings(facets)
            if (str(r.get("name", "")), str(r.get("version", ""))) != own
        ]
        return facets, siblings

    @staticmethod
    def identity(ecosystem: str, content: Any) -> tuple[str, str]:
        """The package's own name and version, as its manifest states them: a release is never its own sibling."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        if ecosystem in EcosystemRegistry.PACKAGE_JSON_FINGERPRINTS:
            try:
                manifest = ScannedJson.loads(content.text)
            except ValueError:
                return "", ""
            if isinstance(manifest, dict):
                return str(manifest.get("name", "")), str(manifest.get("version", ""))
            return "", ""
        adapter = EcosystemRegistry.get(ecosystem)
        try:
            parsed = adapter.parse_manifest(content) if adapter is not None else None
        except (ValueError, RecursionError):
            # S2: an unreadable manifest names no package, so no sibling is set aside as itself; nothing is dropped.
            parsed = None
        return (
            (str(parsed.name or ""), str(parsed.version or "")) if parsed is not None else ("", "")
        )

    @staticmethod
    def shared(facets: dict[str, str | None], sibling: dict[str, Any]) -> list[str]:
        """The facets a sibling shares with these."""
        return [
            f
            for f in CAMPAIGN_FACETS
            if facets.get(f) and facets.get(f) == sibling["facets"].get(f)
        ]

    def _finding(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        facets: dict[str, str | None],
        siblings: list[dict[str, Any]],
    ) -> Finding:
        first = siblings[0]
        shared = CampaignSiblingDetector.shared(facets, first)
        named = ", ".join(
            f"{r.get('name', '')}@{r.get('version', '')} ({r.get('id', '')})" for r in siblings[:3]
        )
        more = f" and {len(siblings) - 3} more" if len(siblings) > 3 else ""
        return Finding(
            rule_id=SIBLING_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            message=(
                f"Shares its {' and '.join(shared)} with {named}{more}, recorded as malicious: "
                "one campaign's payload republished under another name or version."
            ),
            remediation=(
                "Do not install it until it is reviewed; compare it with the condemned release named."
            ),
            location=Location(path=unit.content.path, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(
                    f"{SIBLING_RULE}:{unit.content.path}:{first.get('id', '')}".encode()
                ),
                redaction=RedactionMode.NONE,
            ),
            explanation=Explanation(
                summary="a variant of a condemned campaign", matched_rule=SIBLING_RULE
            ),
            risk=ctx.scorer.score(Severity.HIGH, Confidence.MEDIUM),
            detector=self.id,
            references=(references.OSV,),
        )
