"""The manifest findings about lifecycle scripts: code a package runs on install, as the developer.

A script outside the allowlist of known tools doing their job; one that pipes a download to a shell,
runs an inline interpreter, or reaches a hostile host; one that runs a file no content detector can
read. Each is reported where the script is declared, graded by what it runs."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.scripts import ManifestScripts
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.dependencies import EcosystemFactsProvider, HookKinds
from cordon_scanner.foundation.models import (
    AUTHOR_TIME_HOOKS,
    INSTALL_TIME_HOOKS,
    Category,
    Confidence,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.ecosystems.base import Manifest
    from cordon_scanner.foundation.models import Hook

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

INLINE_INTERPRETER_NEEDLES = frozenset({"node -e", "python -c"})
"""The `HOSTILE_IN_LIFECYCLE` entries that stand for an inline program, which a lifted program's
own unit answers for."""

PIPE_TO_SHELL = ("| sh", "|sh", "| bash", "|bash", "| python", "|python")

_REQUIRE_ONLY = re.compile(
    r"""^node\s{1,4}-e\s{1,4}["']\s{0,4}(?:try\s{0,4}\{\s{0,4})?require\(\s{0,4}['"](?P<path>\.{1,2}/[^'"\s]{1,200})['"]\s{0,4}\)\s{0,4};?"""
    r"""\s{0,4}(?:\}\s{0,4}catch\s{0,4}(?:\(\s{0,4}\w{0,20}\s{0,4}\))?\s{0,4}\{\s{0,4}\}\s{0,4})?["']$"""
)
"""`node -e "try{require('./postinstall')}catch(e){}"`: an inline command that only loads a file."""

READABLE_HOOK_TARGETS = frozenset(
    {"js", "cjs", "mjs", "ts", "py", "sh", "bash", "rb", "pl", "php", "ps1"}
)
"""Hook targets the content detectors read as source. A binary or extensionless executable is not."""


class LifecycleFindings:
    """The manifest findings about install-time lifecycle scripts."""

    #: Ecosystems whose manifest hooks are the project's own build steps (a Dockerfile's RUN),
    #: judged by the rules that read them in context, not as a dependency's install script.
    BUILD_STEP_HOOKS: ClassVar[frozenset[str]] = frozenset({"image"})
    #: Ecosystems whose manifest can mark a package unpublishable (npm's `"private": true`).
    PRIVATE_FLAG: ClassVar[frozenset[str]] = frozenset({"npm"})

    @classmethod
    def lifecycle_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        if manifest.ecosystem in LifecycleFindings.BUILD_STEP_HOOKS:
            # A Dockerfile's RUN steps are the project's own build, judged by the Dockerfile rules
            # that read them in context (a fetched script piped to a shell, sudo, a remote ADD).
            # Listed as build hooks; graded as a dependency's install script, each was reported twice.
            return
        traits = EcosystemFactsProvider.traits()
        if traits.has_install_scripts(manifest.ecosystem) and SourcePaths.is_editor_extension(
            unit.path
        ):
            # A packaged or installed editor extension: the editor unpacks it and runs its `main`,
            # never npm, so no lifecycle script in it -- its own `postinstall`, or one in a bundled
            # node_modules manifest, which ran when the extension was built -- runs on this
            # machine. 471 of 1,943 popular extensions were blocked for scripts that cannot run.
            # What the extension's code does is read by the code detectors, with its severity.
            return
        scripts, declared = (
            ManifestScripts.npm_scripts(unit)
            if traits.has_install_scripts(manifest.ecosystem)
            else ({}, {})
        )
        for hook in manifest.hooks:
            yield from LifecycleFindings._hook_findings(
                ctx, declared, hook, manifest, scripts, unit
            )

    @staticmethod
    def _hook_findings(
        ctx: ScanContext,
        declared: dict[str, str],
        hook: Hook,
        manifest: Manifest,
        scripts: dict[str, str],
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The findings for one lifecycle hook: what its command runs, and whether that is install-time payload."""
        command = hook.command
        if not command or HookKinds.action_step(hook):
            return
        loader = _REQUIRE_ONLY.match(command.strip())
        if loader:
            # A one-liner whose only act is to load a file beside the manifest is that file,
            # run: graded by what the file is, as `node <file>` would be.
            command = f"node {loader.group('path')}"
        # A program the hook carries inline was lifted into a unit of its own and read by
        # every content detector as install-time code (`core.inline_programs`). Its
        # interpreter flag is then no more a finding than `node install.js` is, and the
        # hook is graded like one that runs a file this scan read.
        programs = [] if loader else InlinePrograms.found(unit.path, hook.name, command)
        lifted = (
            bool(programs)
            and all(p.path in ctx.tree_paths for p in programs)
            # And only a program that can do nothing: no network, no process, no evaluation,
            # no decoding, no credential or system read, no persistence. Whatever one of
            # those does in a hook, a word list judged it before and still does.
            and not any(ManifestScripts._capable(p.path, p.source, ctx) for p in programs)
        )
        tree_command = InlinePrograms.as_file_command(command, programs) if lifted else command

        capabilities: list[Capability] = []
        reasons: list[str] = []

        for needle, capability in HOSTILE_IN_LIFECYCLE:
            if lifted and needle in INLINE_INTERPRETER_NEEDLES:
                continue
            if needle in command:
                capabilities.append(capability)
                reasons.append(f"invokes {needle.strip()!r}")

        if capabilities and ManifestScripts._prints_only(command):
            # A one-liner whose whole effect is a message or an exit. See
            # `INERT_CALL`. The capability it named is real -- `node -e` does
            # evaluate a string -- and what it evaluates is a line of text.
            capabilities = []
            reasons = []

        piped = any(marker in command for marker in PIPE_TO_SHELL)
        if piped:
            capabilities.append(Capability.SPAWN)
            reasons.append("pipes fetched content directly into an interpreter")

        # Case-insensitively, because npm spells one of them `prepublishOnly`.
        install_time = hook.name.lower() in INSTALL_TIME_HOOKS
        if not capabilities:
            # A step whose one-liner only prints is safe to run, and still a hook that runs:
            # recorded below the gate rather than dropped.
            talks = ManifestScripts._prints_only(command)
            if not install_time or (
                not talks and ManifestScripts._is_safe_lifecycle(command, scripts, declared)
            ):
                return
            in_tree, readable, talks, vendored = LifecycleFindings._script_standing(
                command, ctx, declared, hook, manifest, scripts, talks, tree_command, unit
            )
            yield from LifecycleFindings._unrecognised_script_finding(
                command, ctx, hook, in_tree, readable, talks, unit, vendored
            )
            return

        fetch_and_run = Capability.EGRESS in capabilities and (
            piped or Capability.SPAWN in capabilities or Capability.EXECUTE in capabilities
        )

        yield from LifecycleFindings._capability_findings(
            capabilities, command, ctx, fetch_and_run, hook, reasons, unit
        )

    @staticmethod
    def _script_standing(
        command: str,
        ctx: ScanContext,
        declared: dict[str, str],
        hook: Hook,
        manifest: Manifest,
        scripts: dict[str, str],
        talks: bool,
        tree_command: str,
        unit: FileUnit,
    ) -> tuple[tuple[str, ...], bool, bool, bool]:
        """What an unrecognised script's place says about it: whether it only talks, is the project's own, sits in the tree, and can be read by the content detectors."""
        talks = talks and ManifestScripts._is_safe_lifecycle(command, scripts, declared)
        # An install-time script that is not a recognised build step.
        # Reported for existing, rather than for containing a word from
        # a list: `node ./scripts/setup.js` matched no hostile substring
        # and produced nothing, while being the shape most npm
        # compromises actually take. What the referenced file does is a
        # separate question the file detectors answer -- and cannot
        # answer at all if nothing points at it.
        first_party = ManifestScripts._is_first_party(unit.path, ctx) or (
            manifest.ecosystem in LifecycleFindings.PRIVATE_FLAG
            and not ManifestScripts._is_vendored(unit.path)
            and ManifestScripts.unpublishable(unit)
        )
        vendored = not first_party
        in_tree = (
            (unit.path,)
            if hook.kind == "consumerinstall" and unit.path in ctx.install_hook_paths
            else ManifestScripts._targets_in_tree(tree_command, ctx.install_hook_paths, unit.path)
        )
        # A published package's hook that runs only source files inside the package:
        # those files were scanned in this run with install-time escalation, so a
        # payload in them is already reported as what it is. What runs something
        # opaque -- a binary, an inline `-e` string, a file that is not there -- keeps
        # the dependency grading, because then this finding is all there is.
        # Or a file the command hands to a shell, which is shell text whatever its name:
        # `sh configure` and `sh cleanup` are how R installs a source package, and
        # 11 of 300 CRAN packages were blocked on them (review 98). `sh` cannot run a
        # binary, so what it runs is a script this scan read.
        readable = bool(in_tree) and all(
            path.rsplit(".", 1)[-1].lower() in READABLE_HOOK_TARGETS
            # A file `node` is handed is JavaScript, whatever it is called:
            # `node bin/preinstall` runs `bin/preinstall` as source.
            or re.search(
                rf"(?:^|[\s;&|(])(?:node|nodejs|tsx|ts-node|bun)\s+(?:\S*/)?"
                rf"{re.escape(path.rpartition('/')[2])}(?:\s|$)",
                tree_command,
            )
            or re.search(
                rf"(?:^|[\s;&|(])(?:ba|da|z)?sh\s+{re.escape(path)}(?:\s|$)",
                tree_command,
            )
            for path in in_tree
        )
        return in_tree, readable, talks, vendored

    @staticmethod
    def _unrecognised_script_finding(
        command: str,
        ctx: ScanContext,
        hook: Hook,
        in_tree: tuple[str, ...],
        readable: bool,
        talks: bool,
        unit: FileUnit,
        vendored: bool,
    ) -> Iterator[Finding]:
        """The finding for an install-time script that is not a recognised build step, graded by what its place says about it."""
        yield ManifestFinding.finding(
            rule_id="SUSPECT.INSTALL.SCRIPT.001",
            category=Category.SUSPICIOUS,
            # Graded by whose manifest it is and what the command reaches.
            # A dependency's install script is the attack; the project's
            # own, pointing at a file in the same repository that this scan
            # has already read, is a fact worth stating once.
            # And lowered again for an author-time hook, which cannot reach a
            # consumer installing from a registry tarball. See
            # `AUTHOR_TIME_HOOKS`.
            # A hook that runs only the package's own source is recorded, not raised: that
            # source was read here as install-time code and graded on what it does, so the
            # manifest adds only that a hook exists. Raised at MEDIUM it was the only code
            # warning on 9,352 of 234,509 benign units (review 98) and changed no verdict.
            # An author-time hook is recorded too: npm never fires it for a registry
            # install, and the git-dependency case is `SUSPECT.DEPENDENCY.SOURCE.001`'s.
            # At MEDIUM, `prepare: tsdx build` and `prepublish: npm run build` were most of
            # what remained of this warning in the long tail (review 98).
            severity=min(
                (Severity.LOW if readable else Severity.HIGH)
                if vendored
                else Severity.LOW
                if in_tree
                else Severity.MEDIUM,
                Severity.LOW
                if talks or hook.name.lower() in AUTHOR_TIME_HOOKS
                else Severity.CRITICAL,
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
                    + (
                        f" It runs {', '.join(in_tree)}, which this scan read as "
                        f"install-time code; anything it does is reported there."
                        if readable
                        else ""
                    )
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

    @staticmethod
    def _capability_findings(
        capabilities: list[Capability],
        command: str,
        ctx: ScanContext,
        fetch_and_run: bool,
        hook: Hook,
        reasons: list[str],
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The finding for a script whose command matched a hostile capability: a fetch-and-run, or what else it was seen to do."""
        if fetch_and_run:
            yield ManifestFinding.finding(
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
            author_time = hook.name.lower() in AUTHOR_TIME_HOOKS
            yield ManifestFinding.finding(
                rule_id="SUSPECT.INSTALL.SCRIPT.001",
                category=Category.SUSPICIOUS,
                # An author-time hook cannot reach a consumer installing from a
                # registry tarball. See `AUTHOR_TIME_HOOKS`: `unionlabs/union`
                # declares `prepare: svelte-kit sync` and
                # `prepack: svelte-kit sync && svelte-package && publint`, and the
                # `&&` chain is what brought them to this branch rather than the one
                # above -- so the grading had to be applied in both places.
                severity=Severity.MEDIUM if author_time else Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="Install script performs unexpected operations",
                message=(
                    f"The {hook.name!r} script runs automatically during "
                    + ("packing or publishing" if author_time else "install")
                    + " and performs operations a build step does not need. "
                    "Install-time code runs as the user with their full environment."
                    + (
                        " This hook runs on the author's machine rather than on a "
                        "consumer's: npm does not fire it for a package installed "
                        "from a registry tarball, which is how every transitive "
                        "dependency arrives. It does fire for a dependency installed "
                        "from a git URL."
                        if author_time
                        else ""
                    )
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


__all__ = [
    "HOSTILE_IN_LIFECYCLE",
    "INLINE_INTERPRETER_NEEDLES",
    "PIPE_TO_SHELL",
    "READABLE_HOOK_TARGETS",
    "LifecycleFindings",
]
