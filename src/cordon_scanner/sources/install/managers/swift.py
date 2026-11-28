"""Swift Package Manager (`swift build`, `test`, `run`, `package resolve`): every dependency Package.resolved pins, scanned before SwiftPM evaluates it.

SwiftPM compiles and runs each dependency's `Package.swift` manifest while it resolves, and plugins and build tools run during the
build, so the code of a dependency runs while dependencies are being got. What Cordon checks is `Package.resolved`, which pins every
remote dependency to a git `revision`. Each GitHub dependency is fetched as GitHub's tarball of that commit, held to it (the tarball
names the commit it was made from, and that must be the pinned one), and scanned; SwiftPM is then run with
`--disable-automatic-resolution`, so it checks out exactly the pinned revisions, and git's own object hashes make that commit the
same files. A dependency on another host, a branch or local path dependency, and every command that chooses versions
(`package update`, `package add`) are refused: nothing pins their bytes. Packages from a Swift package registry are refused, too.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Sequence


class SwiftPlanner:
    BUILDS: ClassVar[frozenset[str]] = frozenset({"build", "test", "run"})
    RESOLVES: ClassVar[frozenset[str]] = frozenset(
        {"resolve", "show-dependencies", "describe", "dump-package", "dump-symbol-graph", "plugin"}
    )
    CHOOSES: ClassVar[frozenset[str]] = frozenset(
        {"update", "add", "edit", "unedit", "reset", "init"}
    )
    REV: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    GITHUB: ClassVar[re.Pattern[str]] = re.compile(
        r"https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]{0,99})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?"
    )
    ARGUMENT: ClassVar[str] = "--disable-automatic-resolution"

    @classmethod
    def verbs(cls, args: Sequence[str]) -> tuple[str, str | None] | None:
        """`(command, subcommand)`: `build`, or `package` and its subcommand. An option's value (`--package-path DIR`) is no
        command, so each word is tried."""
        words = [a for a in args if not a.startswith("-")]
        for index, word in enumerate(words):
            if word in cls.BUILDS:
                return word, None
            if word == "package":
                return word, words[index + 1] if index + 1 < len(words) else None
        return None

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        found = cls.verbs(args)
        if found is None:
            return False
        command, sub = found
        return command in cls.BUILDS or (command == "package" and sub in cls.RESOLVES | cls.CHOOSES)

    @classmethod
    def arguments(cls, args: Sequence[str]) -> list[str]:
        """The command line Cordon runs: the person's, with SwiftPM told to keep to Package.resolved."""
        out = list(args)
        found = cls.verbs(out)
        if found is not None:
            words = [i for i, a in enumerate(out) if not a.startswith("-")]
            at = next(i for i in words if out[i] == found[0])
            if found[1] is not None:
                at = next(i for i in words if i > at and out[i] == found[1])
            out.insert(at + 1, cls.ARGUMENT)
        return out

    @classmethod
    def plan(cls, args: Sequence[str], project: Path) -> InstallPlan:
        found = cls.verbs(args)
        if found is not None and found[0] == "package" and found[1] in cls.CHOOSES:
            raise InstallRefused(
                f"`swift package {found[1]}` chooses dependency versions, and SwiftPM evaluates each one's Package.swift as it "
                "resolves: Cordon cannot scan them first. Update Package.resolved where you trust the packages, then run this again"
            )
        resolved = project / "Package.resolved"
        if not resolved.is_file():
            raise InstallRefused(
                "no Package.resolved here: SwiftPM evaluates each dependency's Package.swift as it resolves. Write the file where "
                "you trust the dependencies (`swift package resolve`), then run this again"
            )
        return InstallPlan(
            "swift", cls.files(resolved.read_text(encoding="utf-8", errors="replace"))
        )

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("Package.resolved is not JSON Cordon can read") from exc
        pins = document.get("pins") if isinstance(document, dict) else None
        if pins is None and isinstance(document, dict):
            pins = (document.get("object") or {}).get("pins")  # the first format
        if not isinstance(pins, list):
            raise InstallRefused("Package.resolved names no dependencies Cordon can read")
        return [cls.pin(pin) for pin in pins if isinstance(pin, dict)]

    @classmethod
    def pin(cls, pin: dict[str, object]) -> PackageFile:
        name = str(pin.get("identity") or pin.get("package") or "a dependency")[:80]
        raw = pin.get("state")
        state: dict[str, object] = raw if isinstance(raw, dict) else {}
        location = str(pin.get("location") or pin.get("repositoryURL") or "")
        kind = str(pin.get("kind") or "remoteSourceControl")
        revision = str(state.get("revision") or "")
        found = cls.GITHUB.fullmatch(location)
        if kind != "remoteSourceControl" or found is None:
            raise InstallRefused(
                f"{name} comes from {urllib.parse.urlsplit(location).hostname or kind}: Cordon checks Swift packages on GitHub by "
                "the commit Package.resolved pins"
            )
        if not cls.REV.fullmatch(revision):
            raise InstallRefused(f"{name}: Package.resolved pins no commit Cordon can read")
        owner, repo = found.groups()
        return PackageFile(
            "swift",
            f"{owner}/{repo}",
            str(state.get("version") or revision[:12]),
            f"https://codeload.github.com/{owner}/{repo}/tar.gz/{revision}",
            "git-commit",
            bytes.fromhex(revision),
        )


__all__ = ["SwiftPlanner"]
