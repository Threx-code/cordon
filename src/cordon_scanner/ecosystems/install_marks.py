"""What an ecosystem says about the code a package runs when it is installed as a dependency.

`ConsumerHooks` names the hooks its manifest parser reports whose command a package manager runs on the machine of whoever installs
the package (npm's `postinstall`, a pod's `prepare_command`); the install-hook shapes (`SUSPECT.INSTALL.INLINE_PROGRAM.001`,
`SUSPECT.INSTALL.UNREAD.001`) are read off those commands. `NoConsumerHooks` says why an ecosystem has none: the thing a shape
reads (a command string run at install) does not exist there.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


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


@dataclass(frozen=True, slots=True)
class PrivateMark:
    """How an ecosystem's manifest says its package is not for publishing (npm's `"private": true`, Cargo's `publish = false`): the
    files that can carry the mark and the `PrivateMarkReaders` function that reads it. A package so marked is no dependency
    of anyone: its install-time commands are its own project's build, not a consumer's."""

    files: tuple[str, ...]
    reader: str

    def holds(self, path: str, content: FileContent) -> bool:
        tail = path.rpartition("!")[2].rpartition("/")[2]
        if not any(fnmatchcase(tail, pattern) for pattern in self.files):
            return False
        return bool(getattr(PrivateMarkReaders, self.reader)(content))


@dataclass(frozen=True, slots=True)
class NoPrivateMark:
    """An ecosystem whose manifest has no field that marks a package unpublishable, and why."""

    reason: str


PrivateMarkDeclaration = PrivateMark | NoPrivateMark


class PrivateMarkReaders:
    """Each reads one manifest's text for the mark; none raises."""

    CARGO: ClassVar[re.Pattern[str]] = re.compile(r"^publish\s*=\s*(?:false|\[\s*\])", re.MULTILINE)
    PUBSPEC: ClassVar[re.Pattern[str]] = re.compile(
        r"^publish_to:\s*['\"]?none['\"]?\s*(?:#.*)?$", re.MULTILINE
    )
    MAVEN: ClassVar[re.Pattern[str]] = re.compile(
        r"<maven\.deploy\.skip>\s*true\s*</maven\.deploy\.skip>"
    )
    NUGET: ClassVar[re.Pattern[str]] = re.compile(
        r"<IsPackable>\s*false\s*</IsPackable>", re.IGNORECASE
    )

    @staticmethod
    def package_json(content: FileContent) -> bool:
        try:
            data = json.loads(content.text)
        except (ValueError, RecursionError):
            return False
        return isinstance(data, dict) and data.get("private") is True

    @staticmethod
    def cargo(content: FileContent) -> bool:
        return PrivateMarkReaders.CARGO.search(content.text) is not None

    @staticmethod
    def pubspec(content: FileContent) -> bool:
        return PrivateMarkReaders.PUBSPEC.search(content.text) is not None

    @staticmethod
    def classifier(content: FileContent) -> bool:
        """PyPI refuses an upload whose classifiers include `Private :: Do Not Upload`."""
        return "Private :: Do Not Upload" in content.text

    @staticmethod
    def maven(content: FileContent) -> bool:
        return PrivateMarkReaders.MAVEN.search(content.text) is not None

    @staticmethod
    def nuget(content: FileContent) -> bool:
        return PrivateMarkReaders.NUGET.search(content.text) is not None


__all__ = [
    "ConsumerHooks",
    "ConsumerHooksDeclaration",
    "NoConsumerHooks",
    "NoPrivateMark",
    "PrivateMark",
    "PrivateMarkDeclaration",
    "PrivateMarkReaders",
]
