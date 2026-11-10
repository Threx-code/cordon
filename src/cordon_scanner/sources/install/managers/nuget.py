"""NuGet (`dotnet`): every package scanned before dotnet restores it. A package's `build/*.props`
and `.targets` are imported into the next build, and a tool package is a program, so `restore`,
`build`, `run`, `test`, `publish`, `pack`, `add package` and `tool install` are installs.

The resolve is NuGet's own and runs no package code: `dotnet restore --use-lock-file` in the project
writes `packages.lock.json`, downloading into a private folder Cordon deletes, never the person's
global package folder. The project files and locks are saved first and put back if anything blocks.
Cordon fetches each locked package's `.nupkg` from nuget.org and verifies it against the SHA-512
nuget.org's catalog publishes for the whole file. (The lock's own `contentHash` is NuGet's hash of the
package without its repository signature, which only NuGet computes.) The command then runs in
locked mode with a NuGet config whose only source is the folder of scanned packages: NuGet installs
those bytes and checks them against the lock itself, and can fetch nothing else.

`dotnet tool install <id>` takes the version and hash nuget.org publishes for the tool package, scans
that one `.nupkg`, and installs it from a NuGet config whose only source is the folder holding the
scanned file, so dotnet cannot fetch anything else.
"""

from __future__ import annotations

import base64
import dataclasses
import gzip
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
    #: Registration leaves for every version, SemVer 2.0 included (served gzip-compressed).
    REGISTRATION: ClassVar[str] = "https://api.nuget.org/v3/registration5-gz-semver2"
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
        cls,
        args: Sequence[str],
        runner: Runner,
        dotnet: str,
        project: Path,
        packages: Path,
        registries: InstallRegistries,
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
            files = cls.files_in(project, registries)
        except InstallRefused:
            cls.restore(project, saved)
            raise
        plan = InstallPlan("nuget", files)
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @classmethod
    def files_in(cls, project: Path, registries: InstallRegistries) -> list[PackageFile]:
        locks = [
            p
            for p in sorted(project.rglob(cls.LOCK))
            if not any(
                part in cls.SKIPPED_DIRECTORIES for part in p.relative_to(project).parts[:-1]
            )
        ]
        if not locks:
            raise InstallRefused("dotnet resolved but wrote no packages.lock.json")
        seen: dict[str, tuple[str, str]] = {}
        for lock in locks:
            for name, version in cls.locked_packages(lock.read_text(encoding="utf-8")):
                seen.setdefault(f"{name.lower()} {version.lower()}", (name, version))
        return [cls.published(name, version, registries) for name, version in seen.values()]

    @classmethod
    def locked_packages(cls, text: str) -> list[tuple[str, str]]:
        """(id, version) of every package in one `packages.lock.json`: every target framework's,
        projects skipped. A package the lock records without a content hash is refused."""
        try:
            document: dict[str, Any] = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("packages.lock.json could not be read") from exc
        out: list[tuple[str, str]] = []
        for frameworks in (document.get("dependencies") or {}).values():
            for name, entry in (frameworks or {}).items():
                if not isinstance(entry, dict) or entry.get("type") == "Project":
                    continue  # a project reference: the person's own code
                version = str(entry.get("resolved") or "")
                digest = cls._sha512(str(entry.get("contentHash") or ""))
                if not version or digest is None:
                    raise InstallRefused(f"{name} has no resolved version or SHA-512 in the lock")
                out.append((str(name), version))
        return out

    @classmethod
    def published(cls, name: str, version: str, registries: InstallRegistries) -> PackageFile:
        """The `.nupkg` of one version, with the SHA-512 nuget.org's catalog records for the file."""
        lower = name.lower()
        if not re.fullmatch(r"[a-z0-9_.-]{1,100}", lower):
            raise InstallRefused(f"{name[:80]!r} is not a NuGet package id")
        leaf = cls._json(f"{cls.REGISTRATION}/{lower}/{version.lower()}.json", registries)
        entry = leaf.get("catalogEntry")
        catalog = cls._json(entry, registries) if isinstance(entry, str) else {}
        algorithm = str(catalog.get("packageHashAlgorithm") or "")
        digest = cls._sha512(str(catalog.get("packageHash") or ""))
        if algorithm.upper() != "SHA512" or digest is None:
            raise InstallRefused(f"nuget.org publishes no SHA-512 for {name} {version}")
        return cls.package_file(str(catalog.get("id") or name), version, digest)

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
    def locked(args: Sequence[str], config: Path) -> list[str]:
        """The person's command, restoring only what the lock records, from the scanned source only.
        `add package` has already added the reference; what is left is restoring it."""
        verb, rest = args[0], list(args[1:])
        if verb == "add":
            return ["restore", "--locked-mode", "--configfile", str(config)]
        if verb == "restore":
            locked = rest if "--locked-mode" in rest else [*rest, "--locked-mode"]
            return [verb, *locked, "--configfile", str(config)]
        cut = rest.index("--") if "--" in rest else len(rest)
        return [
            verb,
            *rest[:cut],
            "-p:RestoreLockedMode=true",
            f"-p:RestoreConfigFile={config}",
            *rest[cut:],
        ]

    @staticmethod
    def scanned_source(files: Sequence[PackageFile], scanned: Path, source: Path) -> None:
        """The scanned `.nupkg` files under the names a NuGet folder source reads."""
        source.mkdir(mode=0o700, exist_ok=True)
        for file in files:
            target = source / f"{file.name.lower()}.{file.version.lower()}.nupkg"
            target.write_bytes((scanned / file.filename).read_bytes())

    # -- tools ----------------------------------------------------------------------------------

    @classmethod
    def tool(cls, name: str, version: str, registries: InstallRegistries) -> InstallPlan:
        """`dotnet tool install <name>`: the one `.nupkg` nuget.org publishes for that version (the
        newest stable when none is given), with the SHA-512 its catalog records."""
        lower = name.lower()
        if not re.fullmatch(r"[a-z0-9_.-]{1,100}", lower):
            raise InstallRefused(f"{name[:80]!r} is not a NuGet package id")
        file = cls.published(name, version or cls._newest_stable(lower, registries), registries)
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
            data = registries.fetch(url, "nuget")
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            value = json.loads(data)
        except (ValueError, RuntimeError, OSError) as exc:
            raise InstallRefused(
                f"nuget.org answered nothing usable for {url[:120]}: {exc}"
            ) from exc
        return value if isinstance(value, dict) else {}

    @staticmethod
    def source_config(source: Path) -> str:
        """A NuGet config whose only source is the folder of scanned packages."""
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n<configuration>\n  <packageSources>\n'
            "    <clear />\n"
            f'    <add key="cordon-scanned" value={quoteattr(str(source))} />\n'
            "  </packageSources>\n</configuration>\n"
        )


__all__ = ["NuGetPlanner"]
