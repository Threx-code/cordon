"""NuGet (`dotnet`): every package scanned before dotnet restores it. A package's `build/*.props`
and `.targets` are imported into the next build, and a tool package is a program, so `restore`,
`build`, `run`, `test`, `publish`, `pack`, `add package` and `tool install` are installs.

The resolve is NuGet's own and runs no package code: `dotnet restore --use-lock-file` in the project
writes `packages.lock.json`, downloading into a private folder Cordon deletes, never the person's
global package folder. The project files and locks are saved first and put back if anything blocks.
Each package's `contentHash` in the lock is the SHA-512 of its `.nupkg`, which Cordon fetches from
nuget.org, verifies and scans. The command then runs in locked mode, so NuGet restores from that lock
and checks every package against the same hash.

`dotnet tool install <id>` takes the version and hash nuget.org publishes for the tool package, scans
that one `.nupkg`, and installs it from a NuGet config whose only source is the folder holding the
scanned file, so dotnet cannot fetch anything else.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from xml.sax.saxutils import quoteattr

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


class NuGetPlanner:
    #: `dotnet` subcommands that restore (and so import package build files) when run.
    RESTORING: ClassVar[frozenset[str]] = frozenset(
        {"restore", "build", "run", "test", "publish", "pack"}
    )
    TOOL_VERBS: ClassVar[frozenset[str]] = frozenset({"install", "update"})
    FLAT: ClassVar[str] = "https://api.nuget.org/v3-flatcontainer"
    REGISTRATION: ClassVar[str] = "https://api.nuget.org/v3/registration5-semver1"
    LOCK: ClassVar[str] = "packages.lock.json"
    #: What a restore reads or writes beside the project, saved before and put back on a block.
    PROJECT_FILES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:\.(?:cs|fs|vb)proj|\.slnx?|^Directory\.(?:Packages|Build)\.props|^packages\.lock\.json"
        r"|^NuGet\.Config|^nuget\.config)$"
    )
    #: Where restore writes and build output lives: never the person's project files.
    SKIPPED_DIRECTORIES: ClassVar[frozenset[str]] = frozenset(
        {"bin", "obj", ".git", "node_modules"}
    )

    @staticmethod
    def installs(args: Sequence[str]) -> bool:
        if not args:
            return False
        verb, rest = args[0], list(args[1:])
        if verb == "add":
            return "package" in rest[:2]
        if verb == "tool":
            return rest[:1] != [] and rest[0] in NuGetPlanner.TOOL_VERBS
        return verb in NuGetPlanner.RESTORING and "--no-restore" not in rest

    @classmethod
    def saved(cls, project: Path) -> dict[str, bytes]:
        """Every project file and lock under `project`, keyed by its path relative to it."""
        out: dict[str, bytes] = {}
        for path in sorted(project.rglob("*")):
            relative = path.relative_to(project)
            if any(part in cls.SKIPPED_DIRECTORIES for part in relative.parts[:-1]):
                continue
            if path.is_file() and cls.PROJECT_FILES.search(path.name):
                out[relative.as_posix()] = path.read_bytes()
        return out

    @classmethod
    def project(
        cls, args: Sequence[str], runner: Runner, dotnet: str, project: Path, packages: Path
    ) -> InstallPlan:
        """Resolve in the project (saved first: `saved:` entries in the plan's manifests are what to
        restore), downloading only into `packages`."""
        saved = cls.saved(project)
        if not any(not name.endswith(cls.LOCK) for name in saved):
            raise InstallRefused(
                "no .csproj, .fsproj, .vbproj or solution here: dotnet has nothing to restore"
            )
        env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(packages)}
        if args[0] == "add":
            done = runner([dotnet, *args, "--no-restore"], project, env)
            if done.returncode != 0:
                cls.restore(project, saved)
                raise InstallRefused(
                    f"dotnet could not add the package:\n{(done.stderr or done.stdout or '').strip()[-2000:]}"
                )
        done = runner(
            [dotnet, "restore", "--use-lock-file", "--force-evaluate", "--packages", str(packages)],
            project,
            env,
        )
        if done.returncode != 0:
            cls.restore(project, saved)
            raise InstallRefused(
                f"dotnet could not resolve the restore:\n{(done.stderr or done.stdout or '').strip()[-2000:]}"
            )
        try:
            files = cls.files_in(project)
        except InstallRefused:
            cls.restore(project, saved)
            raise
        plan = InstallPlan("nuget", files)
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @classmethod
    def files_in(cls, project: Path) -> list[PackageFile]:
        locks = [
            p
            for p in sorted(project.rglob(cls.LOCK))
            if not any(
                part in cls.SKIPPED_DIRECTORIES for part in p.relative_to(project).parts[:-1]
            )
        ]
        if not locks:
            raise InstallRefused("dotnet resolved but wrote no packages.lock.json")
        seen: dict[str, PackageFile] = {}
        for lock in locks:
            for file in cls.files(lock.read_text(encoding="utf-8")):
                seen.setdefault(file.key, file)
        return list(seen.values())

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        """The packages of one `packages.lock.json`: every target framework's, projects skipped."""
        try:
            document: dict[str, Any] = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("packages.lock.json could not be read") from exc
        out: list[PackageFile] = []
        for frameworks in (document.get("dependencies") or {}).values():
            for name, entry in (frameworks or {}).items():
                if not isinstance(entry, dict) or entry.get("type") == "Project":
                    continue  # a project reference: the person's own code
                version = str(entry.get("resolved") or "")
                digest = cls._sha512(str(entry.get("contentHash") or ""))
                if not version or digest is None:
                    raise InstallRefused(f"{name} has no resolved version or SHA-512 in the lock")
                out.append(cls.package_file(str(name), version, digest))
        return out

    @classmethod
    def package_file(cls, name: str, version: str, digest: bytes) -> PackageFile:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) or not re.fullmatch(
            r"[A-Za-z0-9_.+-]{1,64}", version
        ):
            raise InstallRefused(
                f"{name[:80]!r} {version[:40]!r} is not a NuGet package and version"
            )
        lower_name, lower_version = name.lower(), version.lower()
        return PackageFile(
            "nuget",
            name,
            version,
            f"{cls.FLAT}/{lower_name}/{lower_version}/{lower_name}.{lower_version}.nupkg",
            "sha512",
            digest,
            separator=" ",
        )

    @staticmethod
    def _sha512(value: str) -> bytes | None:
        try:
            digest = base64.b64decode(value, validate=True)
        except ValueError:
            return None
        return digest if len(digest) == 64 else None

    @staticmethod
    def restore(project: Path, saved: dict[str, bytes]) -> None:
        """Put the saved project files back, and remove locks the resolve wrote that were not there."""
        for path in project.rglob(NuGetPlanner.LOCK):
            relative = path.relative_to(project).as_posix()
            if relative not in saved and not any(
                part in NuGetPlanner.SKIPPED_DIRECTORIES for part in Path(relative).parts[:-1]
            ):
                path.unlink()
        for relative, data in saved.items():
            (project / relative).write_bytes(data)

    @staticmethod
    def locked(args: Sequence[str]) -> list[str]:
        """The person's command, restoring only what the lock records."""
        verb, rest = args[0], list(args[1:])
        if verb == "add":
            return []  # the reference was added and the lock written; nothing more to run
        if verb == "restore":
            return [verb, *rest] if "--locked-mode" in rest else [verb, *rest, "--locked-mode"]
        cut = rest.index("--") if "--" in rest else len(rest)
        return [verb, *rest[:cut], "-p:RestoreLockedMode=true", *rest[cut:]]

    # -- tools ----------------------------------------------------------------------------------

    @classmethod
    def tool(cls, name: str, version: str, registries: InstallRegistries) -> InstallPlan:
        """`dotnet tool install <name>`: the one `.nupkg` nuget.org publishes for that version (the
        newest stable when none is given), with the SHA-512 its catalog records."""
        lower = name.lower()
        if not re.fullmatch(r"[a-z0-9_.-]{1,100}", lower):
            raise InstallRefused(f"{name[:80]!r} is not a NuGet package id")
        version = version or cls._newest_stable(lower, registries)
        leaf = cls._json(f"{cls.REGISTRATION}/{lower}/{version.lower()}.json", registries)
        entry = leaf.get("catalogEntry")
        catalog = cls._json(entry, registries) if isinstance(entry, str) else {}
        algorithm = str(catalog.get("packageHashAlgorithm") or "")
        digest = cls._sha512(str(catalog.get("packageHash") or ""))
        if algorithm.upper() != "SHA512" or digest is None:
            raise InstallRefused(f"nuget.org publishes no SHA-512 for {name} {version}")
        file = cls.package_file(str(catalog.get("id") or name), version, digest)
        return InstallPlan("nuget", [dataclasses.replace(file, requested=True)])

    @classmethod
    def _newest_stable(cls, lower: str, registries: InstallRegistries) -> str:
        versions = cls._json(f"{cls.FLAT}/{lower}/index.json", registries).get("versions") or []
        stable = [str(v) for v in versions if "-" not in str(v)]
        if not stable:
            raise InstallRefused(f"nuget.org has no stable version of {lower}")
        return stable[-1]

    @staticmethod
    def _json(url: str, registries: InstallRegistries) -> dict[str, Any]:
        try:
            value = json.loads(registries.fetch(url, "nuget"))
        except (ValueError, RuntimeError, OSError) as exc:
            raise InstallRefused(
                f"nuget.org answered nothing usable for {url[:120]}: {exc}"
            ) from exc
        return value if isinstance(value, dict) else {}

    @staticmethod
    def tool_config(source: Path) -> str:
        """A NuGet config whose only source is the folder of scanned packages."""
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n<configuration>\n  <packageSources>\n'
            "    <clear />\n"
            f'    <add key="cordon-scanned" value={quoteattr(str(source))} />\n'
            "  </packageSources>\n</configuration>\n"
        )


__all__ = ["NuGetPlanner"]
