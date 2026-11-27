"""Julia (`Pkg.instantiate()` and the other commands that install what a manifest pins): every package scanned before Pkg builds it.

Pkg runs a package's `deps/build.jl` as it installs it, and loads its code as soon as it is used, so the code of a dependency runs
while dependencies are being got. What Cordon checks is `Manifest.toml`: every package it pins carries `git-tree-sha1`, the git
hash of the package's files, which Pkg itself checks of what it fetches. Each is fetched from the Pkg server by that hash, held to it
(the hash of the files of the archive, recomputed), and scanned; Pkg then installs the same tree and verifies the same hash, so the
files it loads are the files scanned. A standard-library entry (no tree hash: it ships with Julia) is left alone, a local `path`
dependency is scanned as the project's own code, and an entry taken from a git URL (nothing the Pkg server holds) is refused. A
project dependency the manifest does not pin is refused, and so is every command that resolves versions (`add`, `update`, `develop`,
`resolve`): they choose packages Cordon has not scanned. The binary artifacts a package downloads (its `Artifacts.toml`) are fetched
by Pkg itself and are not read here.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Sequence


class JuliaPlanner:
    SERVER: ClassVar[str] = "https://pkg.julialang.org/package"
    PKG: ClassVar[re.Pattern[str]] = re.compile(
        r"\bPkg\.(instantiate|build|test|precompile|add|develop|dev|update|up|resolve|rm|remove|pin|free)\b"
    )
    RESOLVING: ClassVar[frozenset[str]] = frozenset(
        {"add", "develop", "dev", "update", "up", "resolve", "rm", "remove", "pin", "free"}
    )
    TREE: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    UUID: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,100}")
    MANIFESTS: ClassVar[tuple[str, ...]] = ("Manifest.toml", "JuliaManifest.toml")

    @classmethod
    def verbs(cls, args: Sequence[str]) -> set[str]:
        """The `Pkg.` functions the command line calls."""
        return {found.group(1) for arg in args for found in cls.PKG.finditer(arg)}

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        return bool(cls.verbs(args))

    @classmethod
    def project(cls, args: Sequence[str], here: Path) -> Path:
        """The project directory: `--project=DIR`, else the working directory."""
        for arg in args:
            if arg.startswith("--project="):
                value = arg.partition("=")[2]
                if value and not value.startswith("@"):
                    return (here / value).resolve()
        return here

    @classmethod
    def plan(cls, args: Sequence[str], here: Path) -> InstallPlan:
        resolving = sorted(cls.verbs(args) & cls.RESOLVING)
        if resolving:
            raise InstallRefused(
                f"`Pkg.{resolving[0]}` chooses versions, and Pkg builds and loads what it fetches: Cordon cannot scan "
                "them first. Update Manifest.toml where you trust the packages, then run `Pkg.instantiate()` through Cordon"
            )
        project = cls.project(args, here)
        manifest = next((project / n for n in cls.MANIFESTS if (project / n).is_file()), None)
        if manifest is None:
            raise InstallRefused(
                f"no Manifest.toml in {project.name or project}: Cordon checks `Pkg.instantiate` against the packages "
                "the manifest pins"
            )
        entries = cls.entries(manifest.read_text(encoding="utf-8", errors="replace"))
        declared = cls.declared(project / "Project.toml")
        unpinned = sorted(declared - {name for name, _ in entries})
        if unpinned:
            raise InstallRefused(
                f"Manifest.toml does not pin {', '.join(unpinned[:10])}: Pkg would resolve it, and build what it fetches, "
                "before Cordon could scan it. Resolve it where you trust it, then run this again"
            )
        plan = InstallPlan("julia", cls.files(entries))
        plan.local.extend(cls.paths(entries, project))
        return plan

    @classmethod
    def entries(cls, text: str) -> list[tuple[str, dict[str, object]]]:
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise InstallRefused("Manifest.toml is not TOML Cordon can read") from exc
        # Manifest format 2.0 keeps the packages under `deps`; the first format keeps them at the top.
        deps = document.get("deps")
        tables: dict[str, object] = deps if isinstance(deps, dict) else document
        out: list[tuple[str, dict[str, object]]] = []
        for name, versions in tables.items():
            if not isinstance(versions, list) or not cls.NAME.fullmatch(str(name)):
                continue
            out.extend((name, entry) for entry in versions if isinstance(entry, dict))
        return out

    @classmethod
    def declared(cls, project: Path) -> set[str]:
        """The packages Project.toml depends on directly."""
        if not project.is_file():
            return set()
        try:
            deps = tomllib.loads(project.read_text(encoding="utf-8", errors="replace")).get("deps")
        except tomllib.TOMLDecodeError as exc:
            raise InstallRefused("Project.toml is not TOML Cordon can read") from exc
        return set(deps) if isinstance(deps, dict) else set()

    @classmethod
    def files(cls, entries: Sequence[tuple[str, dict[str, object]]]) -> list[PackageFile]:
        out: list[PackageFile] = []
        for name, entry in entries:
            tree, uuid, version = (
                entry.get("git-tree-sha1"),
                entry.get("uuid"),
                entry.get("version"),
            )
            if entry.get("repo-url") or entry.get("repo-rev"):
                raise InstallRefused(
                    f"{name} comes from a git repository: Cordon checks Julia packages by the tree hash of the Pkg server's copy"
                )
            if entry.get("path"):
                continue
            if tree is None:
                continue  # a standard library: it ships with Julia
            if not (
                isinstance(tree, str)
                and cls.TREE.fullmatch(tree)
                and isinstance(uuid, str)
                and cls.UUID.fullmatch(uuid)
            ):
                raise InstallRefused(f"{name}: a Manifest.toml entry Cordon cannot read")
            out.append(
                PackageFile(
                    "julia",
                    name,
                    str(version or tree[:8]),
                    f"{cls.SERVER}/{uuid}/{tree}",
                    "git-tree-sha1",
                    bytes.fromhex(tree),
                )
            )
        return out

    @classmethod
    def paths(cls, entries: Sequence[tuple[str, dict[str, object]]], project: Path) -> list[Path]:
        """Local `path` dependencies: the project's own code, scanned with the rest."""
        found = []
        for _, entry in entries:
            path = entry.get("path")
            if isinstance(path, str):
                target = (project / path).resolve()
                if target.is_dir() and target.is_relative_to(project.resolve()):
                    found.append(target)
        return found


__all__ = ["JuliaPlanner"]
