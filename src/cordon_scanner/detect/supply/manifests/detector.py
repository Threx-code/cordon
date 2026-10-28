"""Manifest inspection: lifecycle scripts and dependency sources.

This detector covers the single most common supply-chain attack: a lifecycle
script added to a package so that arbitrary code runs during installation, as
the developer, before any other control applies.

Two decisions define it.

**The lifecycle check is an allowlist, not a blocklist.** The attack is *adding
a script*, so enumerating known-bad commands is permanently one step behind
whoever writes the next one. Instead, the set of permitted lifecycle entries is
declared and anything else is a finding, including a changed value for a
permitted key.

**The dependency-source check is about mechanism, not intent.** A dependency
resolved from a git URL, an archive URL or a filesystem path may be entirely
legitimate. The point is that none of the ecosystem's own protections apply to
it: no lockfile integrity hash, no advisory matching, no release-age cooldown.
The finding says the safety net is absent, not that something is wrong.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.models import (
    Category,
    Finding,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.identity_findings import IdentityFindings
from cordon_scanner.detect.supply.manifests.lifecycle_findings import LifecycleFindings
from cordon_scanner.detect.supply.manifests.rule_declarations import DECLARED_RULES
from cordon_scanner.detect.supply.manifests.source_findings import SourceFindings


class ManifestDetector(BaseDetector):
    """Inspects dependency manifests."""

    id = ManifestFinding.DETECTOR
    version = "0.5.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return DECLARED_RULES

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        # Read before the manifest lookup: a wheel's METADATA and an sdist's PKG-INFO are a
        # release's own metadata without being dependency manifests.
        name_risk = list(IdentityFindings.name_risk_findings(unit, ctx))
        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None:
            return name_risk

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return ()

        manifest = ecosystem.parse_manifest(unit.content)
        hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
        if hooks_from_tree is not None:
            # Install-time code that is a file beside the manifest rather than a field in it (an R
            # package's `configure`, a Dart package's `hook/build.dart`), seen from the tree's paths.
            manifest = hooks_from_tree(manifest, ctx.tree_paths)

        if manifest.parse_error:
            # A manifest that could not be read is a manifest whose contents
            # were not checked. Reporting it keeps that from resembling a pass.
            return [
                ManifestFinding.operational(
                    unit.path,
                    f"Could not parse this {ecosystem_id} manifest, so its "
                    f"lifecycle scripts and dependency sources were not "
                    f"checked: {manifest.parse_error}",
                )
            ]

        findings: list[Finding] = []
        findings.extend(LifecycleFindings.lifecycle_findings(manifest, unit, ctx))
        findings.extend(IdentityFindings.confusion_findings(manifest, unit, ctx))
        findings.extend(SourceFindings.source_findings(manifest, unit, ctx))
        findings.extend(IdentityFindings.own_name_findings(manifest, unit, ctx, ecosystem_id))
        findings.extend(name_risk)
        findings.extend(SourceFindings.wrapper_findings(unit, ctx))
        return findings

    # -- Dependency confusion --------------------------------------------

    # -- Lifecycle scripts -----------------------------------------------

    # -- Dependency sources ----------------------------------------------

    # -- Construction ----------------------------------------------------


__all__ = ["ManifestDetector"]
