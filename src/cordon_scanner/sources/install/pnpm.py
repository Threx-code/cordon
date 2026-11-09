"""pnpm, resolved to `pnpm-lock.yaml` alone: `pnpm <install|add|update> --lockfile-only
--ignore-scripts` in a private copy of the manifests. The lockfile names each package and its sha512
integrity; Cordon fetches the tarball from the registry, verifies it, scans it, and `pnpm install
--frozen-lockfile` then installs the same bytes (pnpm checks each tarball against that integrity).

The lockfile is YAML, read here by its fixed layout (lockfile v6 and v9, as pnpm writes them), not by a
YAML library: a top-level `packages:` section whose keys are `name@version` (v6: `/name@version`), each
with a one-line `resolution: {integrity: ..., tarball: ...}` map. Anything outside that layout is
refused, never guessed at.
"""

from __future__ import annotations

import os
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

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


class PnpmLock:
    """The parts of `pnpm-lock.yaml` an install needs: each package's id, integrity and tarball."""

    VERSIONS: ClassVar[frozenset[str]] = frozenset({"6.0", "6.1", "9.0"})
    RESOLUTION: ClassVar[str] = "    resolution: {"

    @classmethod
    def read(cls, text: str) -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
        """(package id -> its resolution map, package name -> who depends on it)."""
        version = next(
            (
                cls.unquote(line.split(":", 1)[1])
                for line in text.splitlines()
                if line.startswith("lockfileVersion:")
            ),
            None,
        )
        if version not in cls.VERSIONS:
            raise InstallRefused(
                "pnpm-lock.yaml is not a lockfile version Cordon reads (6 or 9); upgrade pnpm"
            )
        packages: dict[str, dict[str, str]] = {}
        needed_by: dict[str, set[str]] = {}
        section, current = "", ""
        for raw in text.splitlines():
            line = raw.rstrip()
            depth = len(line) - len(line.lstrip(" "))
            if line and depth == 0:
                section, current = line.rstrip(":").strip(), ""
                continue
            if section not in {"packages", "snapshots"} or not line:
                continue
            if depth == 2 and line.endswith(":"):
                current = cls.unquote(line[2:-1]).removeprefix("/")
                if section == "packages":
                    packages[current] = {}
            elif section == "packages" and current and line.startswith(cls.RESOLUTION):
                if not line.endswith("}"):
                    raise InstallRefused(f"pnpm-lock.yaml: unreadable resolution for {current}")
                packages[current] = cls._flow(line[len(cls.RESOLUTION) : -1], current)
            elif current and depth == 6 and ":" in line:
                item = line.strip()
                close = item.find(item[0], 1) if item[0] in "'\"" else -1
                dependency = item[1:close] if close > 0 else item.split(":", 1)[0]
                needed_by.setdefault(dependency, set()).add(PnpmLock.name(current)[0])
        return packages, needed_by

    @staticmethod
    def unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            return value[1:-1]
        return value

    @staticmethod
    def _flow(body: str, key: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in body.split(","):
            name, colon, value = part.partition(":")
            if not colon:
                raise InstallRefused(f"pnpm-lock.yaml: unreadable resolution for {key}")
            out[name.strip()] = value.strip().strip("'\"")
        return out

    @staticmethod
    def name(key: str) -> tuple[str, str]:
        """`@scope/name@1.2.3(peer@x)` -> (`@scope/name`, `1.2.3`)."""
        bare = key.split("(", 1)[0]
        at = bare.rfind("@")
        if at <= 0:
            raise InstallRefused(f"pnpm-lock.yaml: unreadable package id {key!r}")
        return bare[:at], bare[at + 1 :]


class PnpmPlanner:
    INSTALLS: ClassVar[frozenset[str]] = frozenset(
        {"install", "i", "add", "update", "up", "upgrade"}
    )
    COPIED: ClassVar[tuple[str, ...]] = (
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".npmrc",
        ".pnpmfile.cjs",
    )

    @classmethod
    def plan(
        cls,
        project: Path,
        args: Sequence[str],
        runner: Runner,
        pnpm: str,
        registries: InstallRegistries,
    ) -> InstallPlan:
        if (project / ".pnpmfile.cjs").is_file():
            raise InstallRefused(
                ".pnpmfile.cjs is code pnpm runs while it resolves; Cordon will not run it unread",
                hint="Scan it, then install with pnpm directly, or remove the hook.",
            )
        with PrivateDirectory.made("cordon-pnpm-") as scratch:
            members = NpmPlanner.members(project) + cls.workspace_members(project)
            PrivateDirectory.copy(project, scratch, [*cls.COPIED, *members])
            if not (scratch / "package.json").is_file():
                (scratch / "package.json").write_text("{}\n", encoding="utf-8")
            verb = list(args[:1]) or ["install"]
            argv = [pnpm, *verb, *args[1:], "--lockfile-only", "--ignore-scripts"]
            done = runner(argv, scratch, {**os.environ, "CI": "1"})
            if done.returncode != 0:
                raise InstallRefused(
                    f"pnpm could not resolve the install:\n{(done.stderr or done.stdout).strip()[-2000:]}"
                )
            lock = scratch / "pnpm-lock.yaml"
            if not lock.is_file():
                raise InstallRefused("pnpm resolved but wrote no pnpm-lock.yaml")
            plan = InstallPlan("npm", cls.files(lock.read_text(encoding="utf-8"), registries))
            plan.manifests = {
                name: (scratch / name).read_bytes()
                for name in ("package.json", "pnpm-lock.yaml", *members)
                if (scratch / name).is_file()
            }
            return plan

    @staticmethod
    def workspace_members(project: Path) -> list[str]:
        """Members named in `pnpm-workspace.yaml` (`packages:` list of globs)."""
        spec = project / "pnpm-workspace.yaml"
        if not spec.is_file():
            return []
        patterns = [
            PnpmLock.unquote(line.strip()[2:].split(" #", 1)[0])
            for line in spec.read_text(encoding="utf-8").splitlines()
            if line.startswith((" ", "\t")) and line.strip().startswith("- ")
        ]
        root, out = project.resolve(), []
        for pattern in patterns:
            if pattern.startswith(("/", "!")) or ".." in Path(pattern).parts:
                continue
            for match in sorted(project.glob(pattern)):
                candidate = match / "package.json"
                if candidate.is_file() and root in candidate.resolve().parents:
                    out.append(candidate.relative_to(project).as_posix())
        return sorted(set(out))

    @classmethod
    def files(cls, text: str, registries: InstallRegistries) -> list[PackageFile]:
        packages, needed_by = PnpmLock.read(text)
        out: list[PackageFile] = []
        for key, resolution in packages.items():
            name, version = PnpmLock.name(key)
            label = f"{name}@{version}"
            if resolution.get("type") in {"directory", "link"} or key.startswith("link:"):
                continue  # local code: the person's own
            if "integrity" not in resolution:
                raise InstallRefused(
                    f"{label} is not from a registry (no integrity in pnpm-lock.yaml)"
                )
            tarball = resolution.get("tarball") or NpmIntegrity.tarball(name, version)
            out.append(
                PackageFile(
                    "npm",
                    name,
                    version,
                    registries.admit("npm", label, tarball),
                    "sha512",
                    NpmIntegrity.sha512(resolution["integrity"], label),
                    required_by=tuple(sorted(needed_by.get(name, ()))),
                )
            )
        return out


__all__ = ["PnpmLock", "PnpmPlanner"]
