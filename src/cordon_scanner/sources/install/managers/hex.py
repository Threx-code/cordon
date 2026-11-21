"""Hex (`mix deps.get`): every package scanned before Mix loads its `mix.exs`, which it does as soon
as the package is fetched -- dependency code that runs while dependencies are being got.

So the resolve cannot be Mix's own: `mix deps.get` fetches and loads in one go (even with
`--check-locked`, which fetches an unpinned package before it refuses). What Cordon checks is the
lock. `mix deps` -- which reads only the project's own mix.exs and fetches nothing -- names every
declared dependency and whether the lock pins it; the lock's own entries name what each pinned
package needs. Anything not pinned is refused before Mix runs. Every pinned Hex package is then
fetched from repo.hex.pm, held to the lock's outer checksum (the sha256 of the tarball, which Hex
checks too), scanned, and placed in Hex's package cache, where `mix deps.get` finds it: the bytes
Mix unpacks, and whose mix.exs it loads, are the bytes Cordon scanned.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Sequence


class HexPlanner:
    REPO: ClassVar[str] = "https://repo.hex.pm/tarballs"
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,100}")
    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"[0-9A-Za-z.+-]{1,64}")
    CHECKSUM: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")

    @staticmethod
    def installs(args: Sequence[str]) -> bool:
        return bool(args) and args[0] in ("deps.get", "deps.update")

    @classmethod
    def plan(cls, args: Sequence[str], project: Path) -> InstallPlan:
        if args[0] == "deps.update":
            raise InstallRefused(
                "`mix deps.update` resolves new versions, and Mix runs each fetched package's "
                "mix.exs while it resolves; Cordon cannot scan them first. Update the lock where "
                "you trust the packages, then run `mix deps.get` through Cordon"
            )
        lock = project / "mix.lock"
        if not lock.is_file():
            raise InstallRefused(
                "no mix.lock here: Cordon checks `mix deps.get` against the packages the lock pins"
            )
        return InstallPlan("hex", cls.files(lock.read_text(encoding="utf-8", errors="replace")))

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        """Every package a `mix.lock` pins: Hex packages by their outer checksum; a git dependency
        is refused (nothing pins its bytes)."""
        out: list[PackageFile] = []
        for line in text.splitlines():
            entry = line.strip().rstrip(",")
            if not entry.startswith('"') or ":" not in entry:
                continue
            key, _, value = entry.partition(":")
            value = value.strip()
            name = key.strip().strip('"')
            if value.startswith(("{:git", "{:path")):
                raise InstallRefused(
                    f"{name} comes from {'git' if value.startswith('{:git') else 'a path'}: "
                    "Cordon checks Hex packages by the checksum the lock pins"
                )
            if not value.startswith("{:hex,"):
                continue
            out.append(cls.package_file(name, value))
        return out

    @classmethod
    def package_file(cls, name: str, value: str) -> PackageFile:
        """`{:hex, :name, "version", "inner", [managers], [deps], "repo", "outer"}`: the fields
        read are the first three and the last two, so the dependency list between is never parsed."""
        head = [part.strip() for part in value[1:].split(",", 3)]
        tail = value.rstrip("}").rsplit(",", 2)
        if len(head) < 4 or len(tail) < 3:
            raise InstallRefused(f"{name}: a mix.lock entry Cordon cannot read")
        package = head[1].lstrip(":")
        version = head[2].strip('"')
        repo = tail[1].strip().strip('"')
        outer = tail[2].strip().strip('"')
        if not (cls.NAME.fullmatch(package) and cls.VERSION.fullmatch(version)):
            raise InstallRefused(f"{name}: a mix.lock entry Cordon cannot read")
        if repo != "hexpm":
            raise InstallRefused(f"{package} comes from the {repo[:40]} repository, not hex.pm")
        if not cls.CHECKSUM.fullmatch(outer):
            raise InstallRefused(f"{package} {version} has no outer checksum in mix.lock")
        return PackageFile(
            "hex",
            package,
            version,
            f"{cls.REPO}/{package}-{version}.tar",
            "sha256",
            bytes.fromhex(outer),
            separator=" ",
        )

    @classmethod
    def unpinned(cls, declared: str, lock: str) -> list[str]:
        """What `mix deps.get` would fetch that the lock does not pin: a declared dependency `mix
        deps` shows without `locked at` (path dependencies are the project's own), and a package a
        pinned one needs (not optionally) that has no entry of its own."""
        missing: list[str] = []
        name, scm, locked = "", "", False
        for line in [*declared.splitlines(), "* "]:
            if line.startswith("* "):
                if name and not locked and not cls._local(scm):
                    missing.append(name)
                head = line[2:].split(" ", 1)
                name, scm, locked = head[0], head[1] if len(head) > 1 else "", False
            elif line.strip().startswith("locked at"):
                locked = True
        pinned = {f.name for f in cls.files(lock)}
        for line in lock.splitlines():
            entry = line.strip()
            if not entry.startswith('"') or "{:hex," not in entry:
                continue
            for needed in re.findall(
                r"\{:([a-z0-9_]{1,100}), \"[^\"]{0,200}\", \[([^\]]{0,500})\]\}", entry
            ):
                if needed[0] not in pinned and "optional: true" not in needed[1]:
                    missing.append(needed[0])
        return sorted(set(missing))

    @staticmethod
    def _local(scm: str) -> bool:
        """`mix deps` names a dependency's source in its first parentheses: `(Hex package)`, a git
        URL, or the path of a local one, which is the project's own code."""
        source = scm[1:].split(")", 1)[0] if scm.startswith("(") else scm
        return not (source.startswith("Hex package") or "://" in source or source.endswith(".git"))

    @staticmethod
    def cache() -> Path:
        """Hex's package cache: `$HEX_HOME/packages/hexpm`, `~/.hex` by default."""
        return Path(os.environ.get("HEX_HOME") or Path.home() / ".hex") / "packages" / "hexpm"

    @staticmethod
    def seed(files: Sequence[PackageFile], scanned: Path, cache: Path) -> None:
        cache.mkdir(parents=True, exist_ok=True)
        for file in files:
            (cache / f"{file.name}-{file.version}.tar").write_bytes(
                (scanned / file.filename).read_bytes()
            )


__all__ = ["HexPlanner"]
