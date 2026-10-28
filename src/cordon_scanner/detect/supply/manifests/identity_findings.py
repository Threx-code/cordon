"""The manifest findings about what a published package says it is.

A package with nothing in it but a name worth suspecting (REC-4); a package whose own name is a slip
of a popular one; an npm package whose version is engineered to win resolution -- 99 or above, all
nines -- with an install script of its own and next to no other code: dependency confusion."""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.ecosystems.base import Manifest
from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.rule_ids import (
    CONFUSION_RULE,
)
from cordon_scanner.detect.supply.manifests.scripts import ManifestScripts


class IdentityFindings:
    """The manifest findings about a published package's name and version."""

    @classmethod
    def name_risk_findings(cls, unit: FileUnit, ctx: ScanContext) -> Iterable[Finding]:
        """A published package with nothing in it but a name worth suspecting (`detect.name_risk`).

        Blocks only when the name evidence is strong and there is nothing in the package to run
        and no source to read; otherwise a warning. The package's code, if it has any, is read by
        the content rules on its own merits, so this never has to stand in for them.
        """
        from cordon_scanner.detect.supply.name_risk import RULE, NameRisk, PackageIdentities

        identity = PackageIdentities.read(unit, ctx)
        if identity is None:
            return
        assessment = NameRisk.assess(identity)
        if assessment is None:
            return
        reasons = [signal.reason for signal in assessment.signals]
        yield ManifestFinding.finding(
            rule_id=RULE,
            category=Category.SUSPICIOUS,
            # Below a block it is recorded, not raised: measured on 162,499 long-tail units the
            # warning fell on 5,164 benign releases against 674 of 1,567 no-payload samples, a
            # warning on 3.2% of ordinary packages for signals each common alone (review 98, REC-4).
            severity=Severity.HIGH if assessment.blocks else Severity.LOW,
            confidence=Confidence.MEDIUM if assessment.blocks else Confidence.LOW,
            title="Published package is a name with nothing behind it",
            message=(
                f"{identity.name} {identity.version} "
                + "; ".join(reasons)
                + ". "
                + (
                    "That is the shape of a dependency-confusion probe or a name-squat: the "
                    "name is the whole of the package."
                    if assessment.blocks
                    else "Each of these is common alone; together they are worth a look "
                    "before installing."
                )
            ),
            remediation=(
                "Confirm this is the package you meant, from the publisher you meant. If it was "
                "pulled in by name from a private registry, pin that registry for the scope."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"name: {identity.name} {identity.version} (score {assessment.score})",
            capabilities=[],
            reasons=reasons,
            # The file is the release's own metadata, so the directory it sits in is named for
            # the release: `example-utils-1.0/PKG-INFO` and `test-helpers-2.0/PKG-INFO` are not
            # test fixtures, they are packages whose names contain those words.
            fixture_ceiling=False,
        )

    @classmethod
    def own_name_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext, ecosystem_id: str
    ) -> Iterable[Finding]:
        """A package whose own name is a slip of a popular one.

        The dependency check asks this of what a project installs; a scanned package is asked
        of itself. `aiiohttp`, `cryptograohy` and `botocote` are published with nothing in
        them but the name, waiting for the typo -- there is no code to find, and the name is the
        whole of the evidence.
        """
        from cordon_scanner.detect.supply.dependency import DependencyDetector
        from cordon_scanner.intel.registries.popular import PackageIntel

        if not manifest.name or "node_modules/" in f"/{unit.path}" or "site-packages/" in unit.path:
            return
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return
        name = ecosystem.normalize_name(manifest.name)
        if PackageIntel.is_known_package(ecosystem_id, name):
            return
        target = DependencyDetector._typosquat_target(ecosystem_id, name)
        if target is None:
            return
        # A published artefact: the archive scanned as one, an npm tarball's `package/`, or an
        # extracted sdist, whose root is `<name>-<version>/` by the format's own convention.
        directory = posixpath.basename(unit.path.rpartition("!")[2].rpartition("/")[0])
        sdist_root = re.fullmatch(
            rf"{re.escape(name).replace('-', '[-_.]')}-\d[\w.+!-]{{0,40}}",
            directory.lower().replace("_", "-"),
        )
        # Only the formats this was measured on. Raised for every published format, it blocked
        # plyr, tsibble, pyaml, pytest, istio and the homebrew-core and vcpkg Go snapshots (17 of
        # 34,500 real packages, review 98): there the matched manifest is often not the package's.
        published = (
            ctx.distribution in ("pypi", "npm")
            or sdist_root is not None
            or unit.path.rpartition("!")[2] == "package/package.json"
        )
        yield ManifestFinding.finding(
            rule_id="SUSPECT.TYPOSQUAT.PACKAGE_NAME.001",
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH if published else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Package is named like a popular package",
            message=(
                f"This package calls itself {manifest.name!r}, one slip from the widely used "
                f"{target!r}, and is not itself an established package. A published package "
                f"under a name like this collects the installs meant for the other."
            ),
            remediation=f"Install {target!r} if that is what was meant, and report this one.",
            unit=unit,
            ctx=ctx,
            detail=f"{manifest.name} ~ {target}",
            capabilities=[],
            reasons=[f"one edit from {target}"],
        )

    #: A version that wins semver resolution over any real release: major 99 or above, or every
    #: component all nines (`9.9.9`, `99.99.99`). What winning resolution is for is the attack.
    _WINNING_VERSION = re.compile(r"^(?:(?:\d{3,}|99)\.|9+(?:\.9+){1,3}(?:[-+].*)?$)")

    _CODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts")

    @classmethod
    def confusion_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """An npm package whose version is engineered to win resolution, whose install hook runs a
        script that is not a build step, and which has at most one other code file.

        The three together are the dependency-confusion foothold, and none of them alone is: big
        versions, install hooks and tiny packages are each ordinary. Measured on the npm study half
        (review 98): the shape is 246 of 1,923 malicious units, 3 of them caught by nothing else, and
        0 of 11,255 benign npm units across the random, popular and ecosystem corpora."""
        version = (manifest.version or "").strip()
        if manifest.ecosystem != "npm" or not cls._WINNING_VERSION.match(version):
            return
        if SourcePaths.is_editor_extension(unit.path):
            return
        scripts, declared = ManifestScripts.npm_scripts(unit)
        running = [
            hook
            for hook in manifest.hooks
            if hook.command
            and hook.name.lower() in ("preinstall", "install", "postinstall")
            and not ManifestScripts._prints_only(hook.command)
            and not ManifestScripts._is_safe_lifecycle(hook.command, scripts, declared)
        ]
        if not running:
            return
        root = unit.path.rpartition("/")[0]
        prefix = f"{root}/" if root else ""
        others = [
            path
            for path in ctx.tree_paths
            if path.startswith(prefix)
            and "/node_modules/" not in path[len(prefix) - 1 :]
            and path.endswith(cls._CODE_SUFFIXES)
            and not path.endswith(".d.ts")
            and path not in ctx.install_hook_paths
        ]
        if len(others) > 1:
            return
        hook = running[0]
        yield ManifestFinding.finding(
            rule_id=CONFUSION_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="A version made to win resolution runs code on install",
            message=(
                f"{manifest.name or 'This package'} is version {version}, a version made to win "
                f"resolution, and its {hook.name} script runs {hook.command[:120]!r} with "
                f"{len(others)} other code file(s) in the package: the dependency-confusion shape."
            ),
            remediation=(
                "Do not install it. If the name is your organisation's, scope your registry so the "
                "private package can never be resolved from the public one."
            ),
            unit=unit,
            ctx=ctx,
            detail=hook.name,
            capabilities=[],
            reasons=[f"version {version}", f"{hook.name} runs a non-build script", "no other code"],
        )


__all__ = ["IdentityFindings"]
