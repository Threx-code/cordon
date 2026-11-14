"""yarn, resolved without running a package script.

yarn 1 (classic) has no lockfile-only mode, so it resolves in a private copy of the manifests with
`--ignore-scripts --modules-folder <private>`: packages are unpacked there, none of their code runs, and
the project is not touched. `yarn.lock` gives each package's tarball URL and sha512 integrity; after a
clean scan, `yarn install --frozen-lockfile` installs the same bytes (yarn 1 checks the integrity).

yarn 2 and later resolve with `--mode=update-lockfile` (no fetch into the project, no scripts). Their
lockfile's `checksum` covers yarn's own zip of a package, not the registry tarball, so Cordon asks the
registry for each `name@npm:version`'s published `dist.integrity`, fetches the tarball, and verifies
that. The registry serves fixed bytes for a published version, which `yarn install --immutable` then
installs.

Both lockfiles are read by their fixed layout, never by a YAML library; anything else is refused.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.npm import NpmIntegrity, NpmPlanner
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PackageFile,
    PrivateDirectory,
    Runner,
)
from cordon_scanner.sources.install.pnpm import PnpmLock

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


class YarnLock:
    """Entries of a yarn lockfile: header specs at column 0, two-space indented fields below."""

    @staticmethod
    def entries(text: str) -> list[tuple[str, dict[str, str]]]:
        out: list[tuple[str, dict[str, str]]] = []
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith(" "):
                out.append((line.rstrip(":"), {}))
            elif out and line.startswith("  ") and not line.startswith("   "):
                key, _, value = line.strip().partition(" ")
                out[-1][1][key.rstrip(":")] = PnpmLock.unquote(value)
        return out

    @staticmethod
    def name(header: str) -> str:
        """The package name of a header (`"@scope/a@^1", "@scope/a@^2"` -> `@scope/a`)."""
        first = PnpmLock.unquote(header.split(",", 1)[0])
        at = first.find("@", 1)
        return first[:at] if at > 0 else first


class YarnPlanner:
    INSTALLS: ClassVar[frozenset[str]] = frozenset({"install", "add", "upgrade", "up"})
    COPIED: ClassVar[tuple[str, ...]] = (
        "package.json",
        "yarn.lock",
        ".yarnrc",
        ".yarnrc.yml",
        ".npmrc",
    )

    @classmethod
    def plan(
        cls,
        project: Path,
        args: Sequence[str],
        runner: Runner,
        yarn: str,
        registries: InstallRegistries,
    ) -> InstallPlan:
        modern = cls.modern(project, runner, yarn)
        with PrivateDirectory.made("cordon-yarn-") as scratch:
            members = NpmPlanner.members(project)
            PrivateDirectory.copy(project, scratch, [*cls.COPIED, *members, *cls.tooling(project)])
            if not (scratch / "package.json").is_file():
                (scratch / "package.json").write_text("{}\n", encoding="utf-8")
            verb = list(args[:1]) or ["install"]
            extra = (
                ["--mode=update-lockfile"]
                if modern
                else [
                    "--ignore-scripts",
                    "--no-bin-links",
                    "--non-interactive",
                    "--modules-folder",
                    str(scratch / ".cordon-modules"),
                ]
            )
            done = runner([yarn, *verb, *args[1:], *extra], scratch, {**os.environ, "CI": "1"})
            if done.returncode != 0:
                raise InstallRefused(
                    f"yarn could not resolve the install:\n{(done.stderr or done.stdout).strip()[-2000:]}"
                )
            lock = scratch / "yarn.lock"
            if not lock.is_file():
                raise InstallRefused("yarn resolved but wrote no yarn.lock")
            text = lock.read_text(encoding="utf-8")
            files = (
                cls.modern_files(text, project, registries)
                if modern
                else cls.classic_files(text, registries)
            )
            plan = InstallPlan("npm", files)
            plan.manifests = {
                name: (scratch / name).read_bytes()
                for name in ("package.json", "yarn.lock", *members)
                if (scratch / name).is_file()
            }
            return plan

    @staticmethod
    def modern(project: Path, runner: Runner, yarn: str) -> bool:
        """yarn 2 or later: what `yarn --version` says in this project (it may pin its own yarn)."""
        done = runner([yarn, "--version"], project, {**os.environ})
        first = (done.stdout or "").strip().split(".", 1)[0]
        if done.returncode != 0 or not first.isdigit():
            raise InstallRefused("could not tell which yarn this project uses (`yarn --version`)")
        return int(first) >= 2

    @staticmethod
    def tooling(project: Path) -> list[str]:
        """The project's own yarn release and plugins (`.yarn/releases`, `.yarn/plugins`), which
        yarn 2+ runs to resolve: the project's tooling, as it would run without Cordon."""
        out: list[str] = []
        for folder in ("releases", "plugins"):
            base = project / ".yarn" / folder
            if base.is_dir():
                out += [
                    p.relative_to(project).as_posix()
                    for p in sorted(base.rglob("*"))
                    if p.is_file() and not p.is_symlink()
                ]
        return out[:200]

    @classmethod
    def classic_files(cls, text: str, registries: InstallRegistries) -> list[PackageFile]:
        out: dict[str, PackageFile] = {}
        for header, fields in YarnLock.entries(text):
            name, version = YarnLock.name(header), fields.get("version", "")
            label = f"{name}@{version}"
            resolved = fields.get("resolved", "")
            if not resolved or resolved.startswith(("file:", "link:")):
                continue  # local code: the person's own
            out[label] = PackageFile(
                "npm",
                name,
                version,
                registries.admit("npm", label, resolved),
                "sha512",
                NpmIntegrity.sha512(fields.get("integrity", ""), label),
            )
        return list(out.values())

    @classmethod
    def modern_files(
        cls, text: str, project: Path, registries: InstallRegistries
    ) -> list[PackageFile]:
        server = cls.registry_server(project)
        out: dict[str, PackageFile] = {}
        for header, fields in YarnLock.entries(text):
            resolution = fields.get("resolution", "")
            if header == "__metadata" or "@workspace:" in resolution:
                continue
            name, protocol, version = resolution.rpartition("@npm:")
            if not protocol or not name:
                raise InstallRefused(
                    f"{resolution or header} is not an npm registry package (yarn protocol not checked)"
                )
            label = f"{name}@{version}"
            meta = json.loads(
                registries.fetch(
                    registries.admit(
                        "npm", label, f"{server}/{urllib.parse.quote(name, safe='@/')}/{version}"
                    ),
                    "npm",
                )
            )
            dist = meta.get("dist") if isinstance(meta, dict) else None
            if not isinstance(dist, dict):
                raise InstallRefused(f"the registry has no dist record for {label}")
            out[label] = PackageFile(
                "npm",
                name,
                version,
                registries.admit("npm", label, str(dist.get("tarball") or "")),
                "sha512",
                NpmIntegrity.sha512(str(dist.get("integrity") or ""), label),
            )
        return list(out.values())

    @staticmethod
    def registry_server(project: Path) -> str:
        """`npmRegistryServer` from `.yarnrc.yml`, else the public registry."""
        config = project / ".yarnrc.yml"
        if config.is_file():
            for line in config.read_text(encoding="utf-8").splitlines():
                if line.startswith("npmRegistryServer:"):
                    return PnpmLock.unquote(line.split(":", 1)[1]).rstrip("/")
        return "https://registry.npmjs.org"


__all__ = ["YarnLock", "YarnPlanner"]
