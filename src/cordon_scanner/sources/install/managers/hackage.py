"""Haskell (`cabal`): every package `cabal.project.freeze` pins, held to the SHA-256 Hackage's signed index states, scanned before cabal builds it.

Cabal compiles a package and runs its `Setup.hs` (arbitrary Haskell) as it builds it, so a dependency's code runs while dependencies are
being got. `cabal.project.freeze` pins each package to a version; the SHA-256 of each release is in `01-index.tar`, which Hackage's TUF
metadata signs (`hackage_trust.py`: root keys pinned as cabal pins them, timestamp, snapshot). The index is kept in the scanner's cache
directory and brought up to date by fetching only its appended tail (`hackage_index.py`). A package the signed index holds no hash for is
refused. `source-repository-package` (a git dependency) in `cabal.project` is refused: nothing signs it.

What this does not cover: a package the freeze does not pin is chosen by cabal's own solver when it runs, after the scan. Cabal's
`--dry-run` plan would show them; reading it needs a cabal binary this is not yet tested with, so a freeze that is incomplete is not detected.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class HackagePlanner:
    #: The `cabal` commands that download and build packages (`v2-` and `new-` are older spellings).
    GUARDED: ClassVar[frozenset[str]] = frozenset(
        {"build", "install", "run", "test", "bench", "repl", "haddock", "fetch"}
    )
    HOST: ClassVar[str] = "https://hackage.haskell.org/package"
    CONSTRAINT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:any\.|[A-Za-z][A-Za-z0-9-]*:)?([A-Za-z][A-Za-z0-9-]*)\s*==\s*([0-9][0-9.]*)\s*,?"
    )
    #: Packages the compiler supplies: freeze lists them, cabal never downloads them, and the index holds no release of them.
    BUNDLED: ClassVar[frozenset[str]] = frozenset(
        {
            "ghc",
            "ghc-bignum",
            "ghc-boot",
            "ghc-boot-th",
            "ghc-heap",
            "ghc-internal",
            "ghc-platform",
            "ghc-prim",
            "ghci",
            "integer-gmp",
            "libiserv",
            "rts",
            "system-cxx-std-lib",
        }
    )
    GIT: ClassVar[re.Pattern[str]] = re.compile(r"^\s*source-repository-package\b", re.MULTILINE)

    @classmethod
    def verb(cls, args: Sequence[str]) -> str:
        for word in args:
            if not word.startswith("-"):
                return word.removeprefix("v2-").removeprefix("new-")
        return ""

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        return cls.verb(args) in cls.GUARDED

    @classmethod
    def plan(
        cls,
        args: Sequence[str],
        project: Path,
        hashes: Callable[[set[tuple[str, str]]], dict[tuple[str, str], dict[str, str]]],
    ) -> InstallPlan:
        freeze = project / "cabal.project.freeze"
        if not freeze.is_file():
            raise InstallRefused(
                "no cabal.project.freeze here: cabal would choose package versions and build them (running each Setup.hs) as it gets them. "
                "Run `cabal freeze` where you trust the packages, then run this again"
            )
        project_file = project / "cabal.project"
        if project_file.is_file() and cls.GIT.search(
            project_file.read_text(encoding="utf-8", errors="replace")
        ):
            raise InstallRefused(
                "cabal.project has a source-repository-package: a git dependency no signed index holds a hash for. Cordon cannot "
                "check it; vendor it into the project"
            )
        return cls.files(freeze.read_text(encoding="utf-8", errors="replace"), hashes)

    @classmethod
    def pinned(cls, text: str) -> set[tuple[str, str]]:
        """The (name, version) of each `==` constraint of the freeze's `constraints:` field (flags and stanzas carry none)."""
        lines = text.splitlines()
        out: set[tuple[str, str]] = set()
        inside = False
        for line in lines:
            if line and not line[0].isspace():
                inside = line.startswith("constraints:")
                line = line.partition(":")[2]
            if inside:
                for found in cls.CONSTRAINT.finditer(line):
                    out.add((found.group(1), found.group(2)))
        return out

    @classmethod
    def files(
        cls,
        text: str,
        hashes: Callable[[set[tuple[str, str]]], dict[tuple[str, str], dict[str, str]]],
    ) -> InstallPlan:
        wanted = cls.pinned(text)
        if not wanted:
            raise InstallRefused("cabal.project.freeze pins no package version")
        held = hashes(wanted)
        plan = InstallPlan("hackage")
        for name, version in sorted(wanted):
            if name in cls.BUNDLED and (name, version) not in held:
                continue
            digest = held.get((name, version), {}).get("sha256", "")
            if len(digest) != 64 or set(digest) - set("0123456789abcdef"):
                raise InstallRefused(
                    f"{name[:60]}-{version[:40]}: the signed Hackage index holds no SHA-256 for this release"
                )
            plan.files.append(
                PackageFile(
                    "hackage",
                    name,
                    version,
                    f"{cls.HOST}/{name}-{version}/{name}-{version}.tar.gz",
                    "sha256",
                    bytes.fromhex(digest),
                    separator="-",
                )
            )
        return plan


__all__ = ["HackagePlanner"]
