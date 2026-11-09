"""npm's own resolver, run so that it writes a lockfile and nothing else.

`npm <install|i|add|ci|update> ... --package-lock-only --ignore-scripts` in a private copy of the
project's manifests: npm reads the registry and writes `package-lock.json`, and no package's code is
downloaded to run, let alone run. Workspaces resolve as one tree: every member's `package.json` is
copied with its path, and members (local code, the person's own) are not fetched.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

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


class NpmPlanner:
    INSTALLS: ClassVar[frozenset[str]] = frozenset(
        {"install", "i", "add", "ci", "update", "up", "in", "isntall"}
    )
    COPIED: ClassVar[tuple[str, ...]] = (
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        ".npmrc",
    )
    MAX_MEMBERS: ClassVar[int] = 2_000

    @classmethod
    def plan(
        cls,
        project: Path,
        args: Sequence[str],
        runner: Runner,
        npm: str,
        registries: InstallRegistries,
    ) -> InstallPlan:
        with PrivateDirectory.made("cordon-npm-") as scratch:
            members = cls.members(project)
            PrivateDirectory.copy(project, scratch, [*cls.COPIED, *members])
            if not (scratch / "package.json").is_file():
                (scratch / "package.json").write_text("{}\n", encoding="utf-8")
            sub = list(args[:1]) or ["install"]
            # `ci` installs the lockfile as it stands; resolving it is `install` with the lock kept.
            verb = ["install"] if sub[0] == "ci" else sub
            argv = [
                npm,
                *verb,
                *args[1:],
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ]
            done = runner(argv, scratch, {**os.environ})
            if done.returncode != 0:
                raise InstallRefused(
                    f"npm could not resolve the install:\n{done.stderr.strip()[-2000:]}"
                )
            lock_path = scratch / "package-lock.json"
            if not lock_path.is_file():
                raise InstallRefused("npm resolved but wrote no package-lock.json")
            lock = lock_path.read_bytes()
            plan = InstallPlan("npm", cls.files(json.loads(lock), registries))
            plan.manifests = {
                name: (scratch / name).read_bytes()
                for name in ("package.json", "package-lock.json", *members)
                if (scratch / name).is_file()
            }
            return plan

    @classmethod
    def members(cls, project: Path) -> list[str]:
        """Each workspace member's `package.json`, relative to the project (none without workspaces)."""
        manifest = project / "package.json"
        if not manifest.is_file():
            return []
        try:
            document = json.loads(manifest.read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InstallRefused("package.json is not valid JSON") from exc
        spaces = document.get("workspaces") if isinstance(document, dict) else None
        if isinstance(spaces, dict):
            spaces = spaces.get("packages")
        if not spaces:
            return []
        if not isinstance(spaces, list) or not all(isinstance(s, str) for s in spaces):
            raise InstallRefused("package.json `workspaces` is not a list of paths")
        root = project.resolve()
        out: list[str] = []
        for pattern in spaces:
            if pattern.startswith(("/", "!")) or ".." in Path(pattern).parts:
                continue
            for match in sorted(project.glob(pattern)):
                candidate = match / "package.json"
                if candidate.is_file() and root in candidate.resolve().parents:
                    out.append(candidate.relative_to(project).as_posix())
        if len(out) > cls.MAX_MEMBERS:
            raise InstallRefused(f"more than {cls.MAX_MEMBERS} workspace members")
        return sorted(set(out))

    @classmethod
    def files(cls, lock: dict[str, Any], registries: InstallRegistries) -> list[PackageFile]:
        """Every registry package in a lockfile (v2/v3), with what depends on it."""
        packages = lock.get("packages")
        if not isinstance(packages, dict):
            raise InstallRefused("the lockfile has no `packages` map (npm 7 or later writes one)")
        top = packages.get("")
        root: dict[str, Any] = top if isinstance(top, dict) else {}
        direct = {
            name
            for key in ("dependencies", "devDependencies", "optionalDependencies")
            for name in (root.get(key) or {})
        }
        dependents = cls._dependents(packages)
        out: list[PackageFile] = []
        for path, entry in packages.items():
            if (
                "node_modules/" not in path
                or not isinstance(entry, dict)
                or entry.get("link")
                or entry.get("inBundle")
            ):
                # The root and workspace members are the project; a link is local code; a bundled
                # package is inside its parent's tarball.
                continue
            name = str(entry.get("name") or path.rsplit("node_modules/", 1)[-1])
            version, integrity = str(entry.get("version") or ""), entry.get("integrity")
            url = registries.admit("npm", f"{name}@{version}", entry.get("resolved"))
            out.append(
                PackageFile(
                    "npm",
                    name,
                    version,
                    url,
                    "sha512",
                    NpmIntegrity.sha512(str(integrity or ""), f"{name}@{version}"),
                    requested=path == f"node_modules/{name}" and name in direct,
                    required_by=tuple(sorted(dependents.get(path, ()))),
                )
            )
        return out

    @staticmethod
    def _dependents(packages: dict[str, Any]) -> dict[str, set[str]]:
        """Which packages need each lockfile entry, by node's own lookup: nearest node_modules upward."""
        out: dict[str, set[str]] = {}
        for path, entry in packages.items():
            if not isinstance(entry, dict):
                continue
            needs = {
                name
                for key in ("dependencies", "optionalDependencies", "peerDependencies")
                for name in (entry.get(key) or {})
            }
            who = (
                str(entry.get("name") or path.rsplit("node_modules/", 1)[-1])
                if path
                else "your project"
            )
            for dep in needs:
                base = path
                while True:
                    candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                    if candidate in packages:
                        out.setdefault(candidate, set()).add(who)
                        break
                    if not base:
                        break
                    cut = base.rfind("/node_modules/")
                    base = base[:cut] if cut > 0 else ""
        return out


class NpmIntegrity:
    """Subresource-integrity strings, as npm, pnpm and yarn write them."""

    @staticmethod
    def sha512(value: str, label: str) -> bytes:
        """The sha512 of `sha512-<base64>` (the first one, when several algorithms are listed)."""
        for part in value.split():
            if part.startswith("sha512-"):
                try:
                    digest = base64.b64decode(part.removeprefix("sha512-"), validate=True)
                except ValueError as exc:
                    raise InstallRefused(f"{label} has a malformed sha512 integrity") from exc
                if len(digest) == 64:
                    return digest
        raise InstallRefused(f"{label} has no sha512 integrity (a sha1 alone is too weak to trust)")

    @staticmethod
    def tarball(name: str, version: str, registry: str = "https://registry.npmjs.org") -> str:
        """The public registry's tarball URL for `name@version` (scoped names keep their scope)."""
        import urllib.parse

        base = name.rsplit("/", 1)[-1]
        return f"{registry}/{urllib.parse.quote(name, safe='@/')}/-/{base}-{version}.tgz"


__all__ = ["NpmIntegrity", "NpmPlanner"]
