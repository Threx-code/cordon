"""What cabal is given to build from: a private repository made only of the scanned tarballs.

A `file+noindex` repository is a folder of `<name>-<version>.tar.gz` files, with an optional `<name>-<version>.cabal` beside a tarball
that replaces the .cabal file inside it (how cabal reads a revision there: proved on data-forced 0.3.0.0, whose revision 1 widens `base`).
Cabal runs with a private `--config-file` that names that repository and no other, so its solver can choose only a package that was held
to its signed SHA-256 and scanned; anything else is `unknown package`, at the solve, before a download is possible (there is no remote).
The user's own cabal config and extra repositories are therefore not used for a guarded install. Each package's latest .cabal revision
comes from the verified index, so the build matches what Hackage would serve.

Cabal's shared store (`~/.cabal/store`) cannot hand back code other than the tarball scanned: a unit's id is a hash of its inputs, and one
input is the SHA-256 of the source tarball (cabal-install 3.14.1.1, `Distribution/Client/PackageHash.hs`: `pkgHashSourceHash` in
`PackageHashInputs`, written into the hash as `entry "src" showHashValue pkgHashSourceHash`; `ProjectPlanning.hs` fills it with
`readFileHashValue tarball` for a repository that publishes no hashes, as this one). Shown in the `haskell` image with the network off:
split-0.2.5.1 built from the real tarball is store unit `...-117f4e87...`; the same name and version from a tarball with one comment
added is rebuilt as a different unit, `...-f8edb595...`. What the hash does not include is the revised .cabal beside the tarball; a revision
changes bounds and metadata, and the solver's choice of dependencies is part of the hash.
"""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallRefused

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from cordon_scanner.sources.install.plan import InstallPlan


class HackageRepository:
    NAME: ClassVar[str] = "cordon-scanned"
    SAFE: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}")
    #: Settings of a project that name where packages come from; the private repository must be the only one.
    OWN_SOURCES: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(source-repository-package|repository|active-repositories)\b", re.MULTILINE
    )
    CONFIG_FLAGS: ClassVar[tuple[str, ...]] = (
        "--config-file",
        "-z",
        "--project-file",
        "--project-dir",
    )

    @classmethod
    def refuse_own_sources(cls, texts: dict[str, str], args: Sequence[str]) -> None:
        for name, text in texts.items():
            found = cls.OWN_SOURCES.search(text)
            if found:
                raise InstallRefused(
                    f"{name} sets `{found.group(1)}`: a guarded cabal install builds only from the packages Cordon scanned, in a "
                    "repository of its own, so a project that names other package sources cannot be checked. Vendor the package "
                    "into the project, or run cabal where you trust it"
                )
        for word in args:
            if word.split("=", 1)[0] in cls.CONFIG_FLAGS:
                raise InstallRefused(
                    f"`{word.split('=', 1)[0]}` points cabal at a configuration Cordon does not control: a guarded install uses its own"
                )

    @classmethod
    def build(
        cls,
        plan: InstallPlan,
        scanned: Path,
        revisions: dict[tuple[str, str], bytes],
        repository: Path,
    ) -> None:
        """Copy each scanned tarball into `repository` as `<name>-<version>.tar.gz`, with its latest .cabal revision beside it."""
        repository.mkdir(parents=True, exist_ok=True, mode=0o700)
        for file in plan.files:
            stem = f"{file.name}-{file.version}"
            if not cls.SAFE.fullmatch(stem):
                raise InstallRefused(f"{stem[:80]}: a package name cabal's repository cannot hold")
            shutil.copyfile(scanned / file.filename, repository / f"{stem}.tar.gz")
            revision = revisions.get((file.name, file.version))
            if revision:
                (repository / f"{stem}.cabal").write_bytes(revision)

    @classmethod
    def config(cls, repository: Path) -> str:
        return f"repository {cls.NAME}\n  url: file+noindex://{repository}\n"

    @classmethod
    def arguments(cls, args: Sequence[str], config: Path) -> list[str]:
        """The command line cabal runs with: the private configuration first, then what the person typed."""
        return [f"--config-file={config}", *args]


__all__ = ["HackageRepository"]
