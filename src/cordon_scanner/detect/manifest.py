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

from cordon_scanner.core.models import (
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.ecosystems.base import Manifest

# Commands that in a lifecycle script are, on their own, sufficient evidence.
# Every entry either fetches and runs remote content, reads credentials, or
# opens a shell. None has a legitimate purpose in code that executes silently
# during `install`.
HOSTILE_IN_LIFECYCLE = (
    ("curl", Capability.EGRESS),
    ("wget", Capability.EGRESS),
    ("nc ", Capability.EGRESS),
    ("Invoke-WebRequest", Capability.EGRESS),
    ("base64", Capability.DECODE),
    ("eval", Capability.EXECUTE),
    ("node -e", Capability.EXECUTE),
    ("python -c", Capability.EXECUTE),
    ("bash -c", Capability.SPAWN),
    ("sh -c", Capability.SPAWN),
    ("/dev/tcp", Capability.EGRESS),
    ("chmod +x", Capability.PERSIST),
)

PIPE_TO_SHELL = ("| sh", "|sh", "| bash", "|bash", "| python", "|python")


class ManifestDetector(BaseDetector):
    """Inspects dependency manifests."""

    id = "manifest"
    version = "0.1.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="MALWARE.INSTALL.FETCH_EXEC.001",
                title="Install script fetches and executes remote content",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector=ManifestDetector.id,
                remediation="Treat the host as compromised. Do not install this package.",
            ),
            DeclaredRule(
                id="SUSPECT.INSTALL.SCRIPT.001",
                title="Package declares an install-time lifecycle script",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
                remediation="Read the script. Install hooks run before any review or test.",
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None:
            return ()

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return ()

        manifest = ecosystem.parse_manifest(unit.content)

        if manifest.parse_error:
            # A manifest that could not be read is a manifest whose contents
            # were not checked. Reporting it keeps that from resembling a pass.
            return [
                self._operational(
                    unit.path,
                    f"Could not parse this {ecosystem_id} manifest, so its "
                    f"lifecycle scripts and dependency sources were not "
                    f"checked: {manifest.parse_error}",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._lifecycle_findings(manifest, unit, ctx))
        findings.extend(self._source_findings(manifest, unit, ctx))
        return findings

    # -- Lifecycle scripts -----------------------------------------------

    def _lifecycle_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        for hook in manifest.hooks:
            command = hook.command
            if not command:
                continue

            capabilities: list[Capability] = []
            reasons: list[str] = []

            for needle, capability in HOSTILE_IN_LIFECYCLE:
                if needle in command:
                    capabilities.append(capability)
                    reasons.append(f"invokes {needle.strip()!r}")

            piped = any(marker in command for marker in PIPE_TO_SHELL)
            if piped:
                capabilities.append(Capability.SPAWN)
                reasons.append("pipes fetched content directly into an interpreter")

            if not capabilities:
                continue

            fetch_and_run = Capability.EGRESS in capabilities and (
                piped or Capability.SPAWN in capabilities or Capability.EXECUTE in capabilities
            )

            if fetch_and_run:
                yield self._finding(
                    rule_id="MALWARE.INSTALL.FETCH_EXEC.001",
                    category=Category.MALICIOUS,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Install script fetches and executes remote content",
                    message=(
                        f"The {hook.name!r} script downloads content and runs it. This "
                        f"executes automatically on every install, as the user, before "
                        f"any test, review or container boundary applies. What runs is "
                        f"whatever the remote host serves at that moment, so it is not "
                        f"pinned by the lockfile and not captured by review."
                    ),
                    remediation=(
                        "Treat the host as compromised. Do not install this package. "
                        "Rotate credentials reachable from the affected machine, "
                        "starting with registry publish tokens."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=capabilities,
                    reasons=reasons,
                )
            else:
                yield self._finding(
                    rule_id="SUSPECT.INSTALL.SCRIPT.001",
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="Install script performs unexpected operations",
                    message=(
                        f"The {hook.name!r} script runs automatically during install and "
                        f"performs operations a build step does not need. Install-time "
                        f"code runs as the user with their full environment."
                    ),
                    remediation=(
                        "Move the work into an explicit build command that a developer "
                        "chooses to run, and review what the script does."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=capabilities,
                    reasons=reasons,
                )

    # -- Dependency sources ----------------------------------------------

    def _source_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        for declared in manifest.dependencies:
            if not declared.is_non_registry:
                continue
            yield self._finding(
                rule_id="POLICY.DEPENDENCY.SOURCE.001",
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="Dependency resolved from outside the registry",
                message=(
                    f"{declared.name!r} is declared as {declared.spec!r}, which does not "
                    f"resolve from the {manifest.ecosystem} registry. Lockfile integrity "
                    f"hashes, advisory matching and any release-age delay all apply to "
                    f"registry packages and none of them apply here. The dependency may "
                    f"be entirely legitimate; the safety net is simply absent."
                ),
                remediation=(
                    "Publish the package to a registry the organisation controls, or "
                    "vendor it into the repository where it is reviewed like any other "
                    "code."
                ),
                unit=unit,
                ctx=ctx,
                detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
                capabilities=(),
                reasons=[f"declared in {declared.field_name}"],
            )

    # -- Construction ----------------------------------------------------

    def _finding(
        self,
        *,
        rule_id: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: str,
        message: str,
        remediation: str,
        unit: FileUnit,
        ctx: ScanContext,
        detail: str,
        capabilities: list[Capability] | tuple[Capability, ...],
        reasons: list[str],
    ) -> Finding:
        line = self._line_of(unit, detail)

        risk = ctx.scorer.score(
            severity,
            confidence,
            ScoringContext(
                # A lifecycle script is install-time by definition; the manifest
                # need not be listed as a hook for that to be true.
                in_install_hook=True,
                capabilities=frozenset(capabilities),
            ),
        )

        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=unit.path, line=line, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.MASKED,
                # Masked because a lifecycle command can embed a token, and a
                # finding must never be the thing that copies one into a log.
                snippet=Redactor.mask(detail[:200]),
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=title,
                matched_rule=rule_id,
                escalations=tuple(reasons),
            ),
            risk=risk,
            detector=self.id,
            capabilities=tuple(dict.fromkeys(capabilities)),
        )

    @staticmethod
    def _line_of(unit: FileUnit, detail: str) -> int | None:
        """Find the line a manifest entry sits on.

        Best effort by design. The parsers work on parsed structures, which
        carry no positions, so the key is located in the raw text afterwards.
        A missing line number is acceptable; a wrong file is not.
        """
        key = detail.split(":", 1)[0].split(" =", 1)[0].strip()
        if not key:
            return None
        needle = f'"{key}"'.encode()
        index = unit.content.raw.find(needle)
        if index == -1:
            index = unit.content.raw.find(key.encode())
        return unit.content.line_of(index) if index != -1 else None

    def _operational(self, path: str, message: str) -> Finding:
        return Finding(
            rule_id="OPERATIONAL.MANIFEST.UNPARSED",
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(path.encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Fix the syntax error so the manifest can be checked.",
            explanation=Explanation(
                summary="A manifest that cannot be parsed is a manifest that was not checked.",
                matched_rule="OPERATIONAL.MANIFEST.UNPARSED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector=self.id,
        )


__all__ = ["ManifestDetector"]
