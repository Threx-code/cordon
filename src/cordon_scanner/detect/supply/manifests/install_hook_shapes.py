"""Install hooks whose shape says the scan could not read what they run (reviews/mcp-98/47).

A consumer-time hook (`preinstall`, `install`, `postinstall`) of a package the scanner was handed
runs code on the machine of whoever installs it, before any review. Two shapes leave that code
outside what the content detectors read, and each is a finding on its own:

* `SUSPECT.INSTALL.INLINE_PROGRAM.001`: the command carries a program inline (`node -e '...'`).
  A program the capability rules label nothing in used to be graded as harmless, and it is the
  program an attacker writes to say something or to wait; on the measured sets 93 of 174 malicious
  install-script units carry one and 16 of 11,449 legitimate ones do.
* `SUSPECT.INSTALL.UNREAD.001`: the command hands an interpreter a script the scan does not hold.
  The install reach is incomplete there (`install_reach_incomplete`), and install-time code that was
  not read is a content gap that fails closed.

Not these shapes: a one-liner that only loads a file of the package (graded as that file), a
package-manager guard (a program that checks `npm_execpath` or the user agent and labels nothing),
an author-time hook, and the scanned project's own manifest.
"""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.scripts import ManifestScripts
from cordon_scanner.foundation.models import CONSUMER_TIME_HOOKS, Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.analysis.shared.inline_programs import InlineProgram
    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.ecosystems.base import Manifest
    from cordon_scanner.foundation.models import Finding, Hook

INLINE_RULE: Final = "SUSPECT.INSTALL.INLINE_PROGRAM.001"
UNREAD_RULE: Final = "SUSPECT.INSTALL.UNREAD.001"

_INTERPRETERS: Final = frozenset(
    {
        "node",
        "nodejs",
        "python",
        "python3",
        "py",
        "sh",
        "bash",
        "zsh",
        "dash",
        "ruby",
        "perl",
        "php",
        "deno",
        "ts-node",
        "tsx",
    }
)
_SCRIPT_SUFFIXES: Final = frozenset(
    {"js", "cjs", "mjs", "ts", "py", "sh", "bash", "rb", "pl", "php", "ps1"}
)
_CODE_FLAGS: Final = frozenset(
    {"-e", "-c", "-p", "-r", "-m", "--eval", "--print", "--require", "--import", "--module"}
)
"""Interpreter flags whose next word is code or a module name, never a script file."""
_PREFIXES: Final = frozenset({"sudo", "env", "exec", "command", "nohup", "time"})
_SEGMENTS: Final = re.compile(r"&&|\|\||[;&|\n]")
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_GUARD: Final = re.compile(r"npm_execpath|npm_config_user_agent|npm_command|npm_lifecycle_event")
"""What a package-manager guard reads: the program that refuses an install by the wrong manager."""
_NODE_RESOLVED: Final = (".js", ".cjs", ".mjs", ".ts", "/index.js")


class InstallHookShapes:
    """The two hook shapes, as findings of the manifest detector."""

    PACKAGE_ECOSYSTEMS: ClassVar[frozenset[str]] = frozenset({"npm"})

    @classmethod
    def findings(
        cls,
        hook: Hook,
        command: str,
        programs: list[InlineProgram],
        manifest: Manifest,
        unit: FileUnit,
        ctx: ScanContext,
    ) -> Iterator[Finding]:
        """The findings of one hook: nothing unless it is a consumer-time hook of a package."""
        if (
            hook.name.lower() not in CONSUMER_TIME_HOOKS
            or manifest.ecosystem not in cls.PACKAGE_ECOSYSTEMS
            or cls._first_party(manifest, unit, ctx)
        ):
            return
        carried = [p for p in programs if not cls._guard(p, ctx)]
        if carried:
            yield cls._inline_finding(hook, command, unit, ctx)
        missing = cls.unread_targets(command, unit.path, ctx.tree_paths)
        if missing:
            yield cls._unread_finding(hook, command, missing, unit, ctx)

    @classmethod
    def _first_party(cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext) -> bool:
        """Whether the manifest is the scanned project's own: the same test the install-script grading uses."""
        return ManifestScripts._is_first_party(unit.path, ctx) or (
            manifest.ecosystem in cls.PACKAGE_ECOSYSTEMS
            and not ManifestScripts._is_vendored(unit.path)
            and ManifestScripts.unpublishable(unit)
        )

    @staticmethod
    def _guard(program: InlineProgram, ctx: ScanContext) -> bool:
        """A package-manager guard: reads what the manager says about itself and does nothing the capability rules label."""
        return bool(_GUARD.search(program.source)) and not ManifestScripts._capable(
            program.path, program.source, ctx
        )

    @classmethod
    def unread_targets(cls, command: str, manifest_path: str, tree: frozenset[str]) -> list[str]:
        """The script files the command hands an interpreter that the scan does not hold, as the command spells them."""
        base = manifest_path.rpartition("/")[0]
        missing: list[str] = []
        for segment in _SEGMENTS.split(command):
            if ManifestScripts._only_prints(segment.strip()):
                continue
            target = cls._script_argument(segment)
            if target is None:
                continue
            stem = posixpath.normpath(f"{base}/{target}" if base else target)
            if stem.startswith(".."):
                continue
            candidates = {stem, *(f"{stem}{suffix}" for suffix in _NODE_RESOLVED)}
            if not candidates & tree and target not in missing:
                missing.append(target)
        return missing

    @staticmethod
    def _script_argument(segment: str) -> str | None:
        """The script an interpreter is handed in one command segment, spelled relative to the package; None when the segment
        runs no script, or one that cannot be a file of the package (a variable, a URL, an absolute path, a dependency's bin)."""
        words = segment.strip().lstrip("@-").split()
        while words and (_ASSIGNMENT.match(words[0]) or words[0] in _PREFIXES):
            words = words[1:]
        if not words or posixpath.basename(words[0]) not in _INTERPRETERS:
            return None
        for word in words[1:]:
            if word in _CODE_FLAGS:
                return None
            if word.startswith("-"):
                continue
            target = re.sub(r"^(?:\./)+", "", word.strip("\"'`"))
            suffix = posixpath.basename(target).rpartition(".")[2].lower()
            if (
                not target
                or target.startswith(("/", "~"))
                or any(mark in target for mark in ("$", "`", "*", "://", "node_modules"))
                or ("." in posixpath.basename(target) and suffix not in _SCRIPT_SUFFIXES)
            ):
                return None
            return target
        return None

    @staticmethod
    def _inline_finding(hook: Hook, command: str, unit: FileUnit, ctx: ScanContext) -> Finding:
        return ManifestFinding.finding(
            rule_id=INLINE_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            title="Install hook carries its program inline",
            message=(
                f"The {hook.name!r} script runs automatically during install and carries a program "
                f"in the command itself ({command!r}), outside any file a reviewer opens. A program "
                f"the capability rules find nothing in is the one an install hook uses to say "
                f"something or to wait, and installed packages that carry one are almost all "
                f"malicious on the measured sets."
            ),
            remediation=(
                "Move the program into a file of the package, where it is read like any other "
                "install-time code, or drop the hook."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{hook.name}: {command}",
            capabilities=[],
            reasons=["an install hook carries its program inline"],
        )

    @staticmethod
    def _unread_finding(
        hook: Hook, command: str, missing: list[str], unit: FileUnit, ctx: ScanContext
    ) -> Finding:
        return ManifestFinding.finding(
            rule_id=UNREAD_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            title="Install hook runs a script this scan does not hold",
            message=(
                f"install_reach_incomplete: the {hook.name!r} script runs automatically during "
                f"install and hands an interpreter {', '.join(repr(m) for m in missing)} "
                f"({command!r}), which is not a file of this scan. The code that runs at install "
                f"was not read, so nothing here can say what it does."
            ),
            remediation=(
                "Ship the script in the package so it is read, or drop the hook; if it must run "
                "from elsewhere, suppress this finding with a justification."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{hook.name}: {command}",
            capabilities=[],
            reasons=["install-time code the scan could not read"],
        )


__all__ = ["INLINE_RULE", "UNREAD_RULE", "InstallHookShapes"]
