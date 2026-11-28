"""What an ecosystem says about the code a package runs when it is installed as a dependency.

`ConsumerHooks` names the hooks its manifest parser reports whose command a package manager runs on the machine of whoever installs
the package (npm's `postinstall`, a pod's `prepare_command`); the install-hook shapes (`SUSPECT.INSTALL.INLINE_PROGRAM.001`,
`SUSPECT.INSTALL.UNREAD.001`) are read off those commands. `NoConsumerHooks` says why an ecosystem has none: the thing a shape
reads (a command string run at install) does not exist there.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True, slots=True)
class ConsumerHooks:
    """The hook names (patterns) whose commands run when a dependency is installed or built. `measured`: the shapes were measured
    on this ecosystem's published packages and may block; elsewhere they are reported below the gate."""

    names: tuple[str, ...]
    measured: bool = False

    def holds(self, name: str) -> bool:
        return any(fnmatchcase(name.lower(), pattern.lower()) for pattern in self.names)


@dataclass(frozen=True, slots=True)
class NoConsumerHooks:
    """An ecosystem that runs no command string of a dependency when it is installed, and why."""

    reason: str


ConsumerHooksDeclaration = ConsumerHooks | NoConsumerHooks

__all__ = ["ConsumerHooks", "ConsumerHooksDeclaration", "NoConsumerHooks"]
