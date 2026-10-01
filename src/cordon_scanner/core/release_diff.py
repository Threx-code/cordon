"""What a release added, compared with the release before it.

An attacker can disguise code; they cannot hide that it changed. The compromises that matter most
-- a maintainer account taken over, a malicious version pushed to a long-trusted package -- look
like this from the outside: a package that never ran anything at install suddenly does, install
code that never touched the network suddenly fetches and executes, a readable package ships an
obfuscated file. Each of those is a fact about the difference between two artefacts, and it holds
however the new code is written.

`Profile.of` reduces a scan result to the facts that matter; `compare` reports what the newer one
gained. It never lowers or removes a finding of the release itself: the diff adds evidence, it
does not excuse.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Capability, Category, Severity
from cordon_scanner.core.taxonomy import AttackCategory

if TYPE_CHECKING:
    from cordon_scanner.core.models import Finding, ScanResult

RELEASE_NEW_HOOK = "SUSPECT.RELEASE.NEW_INSTALL_HOOK.001"
RELEASE_NEW_CAPABILITY = "SUSPECT.RELEASE.NEW_CAPABILITY.001"
RELEASE_NEW_OBFUSCATION = "SUSPECT.RELEASE.NEW_OBFUSCATION.001"
RELEASE_NEW_BINARY = "SUSPECT.RELEASE.NEW_BINARY.001"
RELEASE_NEW_PUBLISHER = "SUSPECT.RELEASE.NEW_PUBLISHER.001"

ACTING_CAPABILITIES = frozenset(
    {
        Capability.EGRESS,
        Capability.SPAWN,
        Capability.EXECUTE,
        Capability.FETCH_EXEC,
        Capability.DECODE,
        Capability.CREDENTIAL,
    }
)
"""The capabilities whose arrival in a release is worth a line: reaching the network, starting a
process, executing or decoding code, reading credentials."""

DECISIVE = frozenset({Capability.FETCH_EXEC, Capability.EXECUTE, Capability.CREDENTIAL})
"""A release that gains one of these in code that runs on its own is blocked, not noted."""

_VERSIONED_ROOT = re.compile(r"^[^/]*?[-_]v?\d+(?:\.\d+){0,3}[^/]*/")


def member(path: str) -> str:
    """A path comparable across releases: the archive name dropped, and a versioned top directory
    (`requests-2.31.0/`, `pkg-1.0.0/`) stripped, so `x-1.0/setup.py` and `x-1.1/setup.py` match."""
    inner = path.rpartition("!")[2]
    return _VERSIONED_ROOT.sub("", inner, count=1)


@dataclass(frozen=True)
class Profile:
    hooks: frozenset[str] = field(default_factory=frozenset)
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    obfuscated: frozenset[str] = field(default_factory=frozenset)
    binaries: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def of(cls, result: ScanResult) -> Profile:
        hooks: set[str] = set()
        capabilities: set[Capability] = set()
        obfuscated: set[str] = set()
        binaries: set[str] = set()
        for finding in result.findings:
            path = member(finding.location.path)
            if finding.attack_category is AttackCategory.INSTALL_HOOK or finding.rule_id.startswith(
                ("SUSPECT.INSTALL.", "MALWARE.INSTALL.")
            ):
                hooks.add(path)
            if finding.category in (Category.MALICIOUS, Category.SUSPICIOUS):
                capabilities.update(c for c in finding.capabilities if c in ACTING_CAPABILITIES)
            if finding.rule_id.startswith("SUSPECT.OBFUSCATION."):
                obfuscated.add(path)
            if finding.rule_id.startswith(("POLICY.BINARY.", "SUSPECT.BINARY.")):
                binaries.add(path)
        return cls(
            frozenset(hooks), frozenset(capabilities), frozenset(obfuscated), frozenset(binaries)
        )


@dataclass(frozen=True)
class Change:
    rule_id: str
    severity: Severity
    path: str
    message: str


def compare(new: Profile, old: Profile, *, previous: str) -> list[Change]:
    """What `new` has that `old` did not, as findings-to-be. `previous` names the older release."""
    changes: list[Change] = []
    added_hooks = sorted(new.hooks - old.hooks)
    if added_hooks:
        changes.append(
            Change(
                RELEASE_NEW_HOOK,
                Severity.HIGH,
                added_hooks[0],
                f"This release runs code at install that {previous} did not "
                f"({', '.join(added_hooks[:3])}). A package that starts running something on "
                "install is how a taken-over maintainer account turns into a compromise.",
            )
        )
    gained = new.capabilities - old.capabilities
    if gained:
        names = ", ".join(sorted(c.value for c in gained))
        changes.append(
            Change(
                RELEASE_NEW_CAPABILITY,
                Severity.HIGH if gained & DECISIVE or (added_hooks and gained) else Severity.MEDIUM,
                next(iter(sorted(new.hooks))) if new.hooks else ".",
                f"Compared with {previous}, this release's flagged code gains: {names}. "
                "Code that did not reach the network, start processes or execute payloads now does.",
            )
        )
    added_obfuscation = sorted(new.obfuscated - old.obfuscated)
    if added_obfuscation and not old.obfuscated:
        changes.append(
            Change(
                RELEASE_NEW_OBFUSCATION,
                Severity.HIGH,
                added_obfuscation[0],
                f"This release ships obfuscated code; {previous} shipped none "
                f"({', '.join(added_obfuscation[:3])}).",
            )
        )
    added_binaries = sorted(new.binaries - old.binaries)
    if added_binaries:
        changes.append(
            Change(
                RELEASE_NEW_BINARY,
                Severity.MEDIUM,
                added_binaries[0],
                f"This release adds compiled files {previous} did not have "
                f"({', '.join(added_binaries[:3])}).",
            )
        )
    return changes


def as_findings(changes: list[Change], result: ScanResult) -> list[Finding]:
    """The changes as findings anchored in the newer release's own paths."""
    from cordon_scanner.core.engine import Engine

    archive = next(
        (f.location.path.partition("!")[0] for f in result.findings if "!" in f.location.path),
        "",
    )
    out: list[Finding] = []
    for change in changes:
        path = f"{archive}!{change.path}" if archive and change.path != "." else change.path
        out.append(
            Engine.release_change(
                path=path,
                rule_id=change.rule_id,
                message=change.message,
                severity=change.severity,
            )
        )
    return out


__all__ = [
    "RELEASE_NEW_BINARY",
    "RELEASE_NEW_CAPABILITY",
    "RELEASE_NEW_HOOK",
    "RELEASE_NEW_OBFUSCATION",
    "RELEASE_NEW_PUBLISHER",
    "Change",
    "Profile",
    "as_findings",
    "compare",
    "member",
]
