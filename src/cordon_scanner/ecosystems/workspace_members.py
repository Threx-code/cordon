"""The packages a scanned tree defines itself, which a dependency of the same name resolves to instead of
the registry (notes/77-decoy-manifest-silences-dependency-intel.md).

Every manifest's own name used to count, so a package shipping `test-package/package.json` named for
its known-malicious dependency had that dependency marked local, and no advisory was checked. Now a
manifest defines a member only where the ecosystem would resolve a dependency to it:

```
  a published package (the caller checks PackageFormat), or a manifest inside an archive ─► defines nothing: installed as a
      dependency, a package's own workspaces are never resolved, so its ranges come from the registry
  npm family, in a repository ─► the tree's root (no package.json above it), or a member that its
      root declares (package.json `workspaces`, pnpm-workspace.yaml or lerna.json `packages`, npm
      globs with `!` excludes); a dependency resolves to a member only if the member's version
      satisfies the declared range (or the range is `*`, empty, or `workspace:`)
  every other ecosystem ─► as before (its own `defines_members`), counted per ecosystem by the pair
```

A `file:`, `link:` or `workspace:` path spec is local by where it points (`Graph.declared_inside`), not
by this.
"""

from __future__ import annotations

import posixpath
import re
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.formats.scanned_json import ScannedJson

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cordon_scanner.detect.base import FileUnit
    from cordon_scanner.foundation.content import FileContent

    #: `VersionRanges.admits`: whether a range admits a version, by the ecosystem's syntax.
    Admits = Callable[[str, str, str], bool]


class WorkspaceMembers:
    """`(ecosystem, normalized name)` -> the versions its defining manifests carry."""

    NPM_FAMILY: ClassVar[frozenset[str]] = frozenset({"npm"})
    """Ecosystems that resolve a range to a workspace member only when the member satisfies it."""

    def __init__(
        self,
        versions: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
        admits: Admits | None = None,
    ) -> None:
        self._versions = dict(versions or {})
        self._admits = admits

    def __bool__(self) -> bool:
        return bool(self._versions)

    def __contains__(self, key: object) -> bool:
        return key in self._versions

    def resolves(self, ecosystem: str, name: str, spec: str | None) -> bool:
        """Whether a dependency on `name` at `spec` resolves to a member rather than the registry."""
        versions = self._versions.get((ecosystem, name))
        if versions is None:
            return False
        if ecosystem not in WorkspaceMembers.NPM_FAMILY:
            return True
        spec = (spec or "").strip()
        if spec in ("", "*", "latest", "x") or spec.startswith("workspace:"):
            return True
        admits = self._admits
        return admits is not None and any(v and admits("npm", spec, v) for v in versions)

    @staticmethod
    def collect(
        units: list[FileUnit],
        ecosystem_at: Callable[[str], str | None],
        registered: Callable[[str], Any],
        manifest_of: Callable[..., Any],
        admits: Admits,
    ) -> WorkspaceMembers:
        """The members of a source tree (the caller has ruled out a published package, whose own
        workspaces never resolve on install), with the ecosystem lookups passed in, not imported."""
        found: dict[tuple[str, str], list[str]] = {}
        contents = MappingProxyType({u.path: u.content for u in units})  # Graph.view_of
        for unit in units:
            if (
                "!" in unit.path
                or "node_modules/" in f"/{unit.path}"
                or "site-packages/" in unit.path
            ):
                continue
            ecosystem_id = ecosystem_at(unit.path)
            ecosystem = registered(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            if ecosystem_id in WorkspaceMembers.NPM_FAMILY:
                defines: Any = NpmWorkspaces.defines(unit.path, contents)
            else:
                # For most ecosystems always; never for Homebrew; for Conan only a workspace's members.
                defines = getattr(ecosystem, "defines_members", True)
                if callable(defines):
                    defines = defines(unit.path, contents)
            if not defines:
                continue
            try:  # with the build in view (a Gradle settings script, a Maven parent POM)
                manifest = manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: BLE001, S112
                continue
            if manifest.name:
                key = (ecosystem_id, ecosystem.normalize_name(manifest.name))
                found.setdefault(key, []).append(manifest.version or "")
        return WorkspaceMembers({k: tuple(v) for k, v in found.items()}, admits)


class NpmWorkspaces:
    """Which package.json files an npm, yarn, pnpm or lerna repository declares as its members."""

    @staticmethod
    def defines(path: str, files: Mapping[str, FileContent]) -> bool:
        """The tree's root manifest, or one its root declares as a workspace member."""
        directory = posixpath.dirname(path)
        root = NpmWorkspaces._root(directory, files)
        if root is None:
            return True  # no package.json above it: a root of its own
        relative = directory[len(root) + 1 :] if root else directory
        patterns = NpmWorkspaces._patterns(root, files)
        include = [p for p in patterns if not p.startswith("!")]
        exclude = [p[1:] for p in patterns if p.startswith("!")]
        return any(NpmWorkspaces._matches(relative, p) for p in include) and not any(
            NpmWorkspaces._matches(relative, p) for p in exclude
        )

    @staticmethod
    def _root(directory: str, files: Mapping[str, FileContent]) -> str | None:
        """The top-most directory above `directory` holding a package.json; None when there is none."""
        found: str | None = None
        ancestor = directory
        while ancestor:
            ancestor = posixpath.dirname(ancestor)
            if f"{ancestor}/package.json".lstrip("/") in files:
                found = ancestor
        return found

    @staticmethod
    def _patterns(root: str, files: Mapping[str, FileContent]) -> list[str]:
        prefix = f"{root}/" if root else ""
        out: list[str] = []
        manifest = files.get(f"{prefix}package.json")
        data = NpmWorkspaces._json(manifest)
        workspaces = data.get("workspaces") if isinstance(data, dict) else None
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages")
        if isinstance(workspaces, list):
            out += [w for w in workspaces if isinstance(w, str)]
        lerna = NpmWorkspaces._json(files.get(f"{prefix}lerna.json"))
        if isinstance(lerna, dict) and isinstance(lerna.get("packages"), list):
            out += [w for w in lerna["packages"] if isinstance(w, str)]
        pnpm = files.get(f"{prefix}pnpm-workspace.yaml") or files.get(f"{prefix}pnpm-workspace.yml")
        if pnpm is not None:
            out += NpmWorkspaces._pnpm_packages(pnpm.text)
        return [p.strip().rstrip("/").removeprefix("./") for p in out if p.strip()]

    @staticmethod
    def _json(content: FileContent | None) -> object:
        if content is None:
            return None
        try:
            return ScannedJson.loads(content.text)
        except ValueError:
            return None

    @staticmethod
    def _pnpm_packages(text: str) -> list[str]:
        """The `packages:` list of a pnpm-workspace.yaml: the block's `- item` lines, quotes dropped."""
        out: list[str] = []
        inside = False
        for line in text.splitlines():
            if re.match(r"packages\s*:", line):
                inside = True
                continue
            if inside:
                stripped = line.strip()
                if line[:1] in (" ", "\t") and stripped.startswith("-"):
                    out.append(stripped[1:].strip().strip("'\""))
                elif stripped and not line.startswith((" ", "\t", "#")):
                    inside = False
        return out

    @staticmethod
    def _matches(relative: str, pattern: str) -> bool:
        """npm's workspace globs: `*` within one directory level, `**` across any number."""
        parts, glob = relative.split("/"), pattern.split("/")

        def walk(i: int, j: int) -> bool:
            if j == len(glob):
                return i == len(parts)
            if glob[j] == "**":
                return any(walk(k, j + 1) for k in range(i, len(parts) + 1))
            return i < len(parts) and fnmatchcase(parts[i], glob[j]) and walk(i + 1, j + 1)

        return walk(0, 0)


__all__ = ["NpmWorkspaces", "WorkspaceMembers"]
