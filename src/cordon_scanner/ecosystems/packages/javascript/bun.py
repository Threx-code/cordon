"""bun.lock: its workspaces and packages, read into the dependency graph."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    LockEntry,
    LockGraph,
)
from cordon_scanner.ecosystems.packages.npm import NpmEcosystem
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class BunLock:
    """Bun's text lockfile (`bun.lock`, the default since Bun 1.2).

    JSON with trailing commas. `workspaces` holds each workspace's declared dependencies, keyed by
    its path (`""` is the root); `packages` maps an install path to an array whose first element
    is `name@version`. A registry package's array is `[spec, registry, metadata, integrity]`, with
    an empty registry meaning the default; a workspace, `file:` or `link:` package is the project's
    own code, and a git or tarball package resolves somewhere other than a registry.
    """

    LOCAL_PREFIXES = ("workspace:", "file:", "link:")
    REMOTE_PREFIXES = ("github:", "git+", "git:", "http://", "https://")

    @staticmethod
    def without_trailing_commas(text: str) -> str:
        """The document with every comma that closes an object or array removed, outside strings."""
        out: list[str] = []
        in_string = escaped = False
        pending = ""
        for char in text:
            if in_string:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if pending:
                if char in " \t\r\n":
                    pending += char
                    continue
                out.append(pending[1:] if char in "}]" else pending)
                pending = ""
            if char == ",":
                pending = ","
                continue
            if char == '"':
                in_string = True
            out.append(char)
        out.append(pending)
        return "".join(out)

    @staticmethod
    def split_spec(spec: str) -> tuple[str, str]:
        """`@scope/name@1.2.3` as (`@scope/name`, `1.2.3`); the version is everything after the
        `@` that follows the name."""
        at = spec.find("@", 1)
        return (spec, "") if at <= 0 else (spec[:at], spec[at + 1 :])

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(cls.without_trailing_commas(content.text))
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid bun.lock: {exc}"
            )
        raw_workspaces = data.get("workspaces")
        workspaces: dict[str, Any] = raw_workspaces if isinstance(raw_workspaces, dict) else {}
        declared, development_only, optional_only, member_versions = BunLock._workspace_scopes(
            workspaces
        )
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return LockGraph(path=content.path, ecosystem=ecosystem)
        entries = cls._entries(packages, development_only, optional_only, member_versions, declared)
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            workspaces=tuple(sorted(p for p in workspaces if p)),
        )

    @staticmethod
    def _workspace_scopes(
        workspaces: dict[str, Any],
    ) -> tuple[set[str], set[str], set[Any], dict[str, str]]:
        """What the workspaces declare: the development-only and optional-only names, and each member's version."""
        declared: set[str] = set()
        development: set[str] = set()
        for workspace in workspaces.values():
            if not isinstance(workspace, dict):
                continue
            for field in (
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "devDependencies",
            ):
                section = workspace.get(field)
                if isinstance(section, dict):
                    declared.update(str(name) for name in section)
                    if field == "devDependencies":
                        development.update(str(name) for name in section)
        # Dev only when no workspace also asks for it at runtime.
        development_only = development - {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            for field in ("dependencies", "optionalDependencies", "peerDependencies")
            if isinstance(workspace.get(field), dict)
            for name in workspace[field]
        }
        optional_only = {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            and isinstance(workspace.get("optionalDependencies"), dict)
            for name in workspace["optionalDependencies"]
        } - {
            name
            for workspace in workspaces.values()
            if isinstance(workspace, dict)
            for field in ("dependencies", "peerDependencies", "devDependencies")
            if isinstance(workspace.get(field), dict)
            for name in workspace[field]
        }
        member_versions = {
            str(w.get("name")): str(w.get("version") or "")
            for path, w in workspaces.items()
            if path and isinstance(w, dict) and w.get("name")
        }
        return declared, development_only, optional_only, member_versions

    @classmethod
    def _entries(
        cls,
        packages: dict[Any, Any],
        development_only: set[str],
        optional_only: set[Any],
        member_versions: dict[str, str],
        declared: set[str],
    ) -> list[LockEntry]:
        """One entry per installed package, with its scope, integrity and edges."""
        entries: list[LockEntry] = []
        for location, value in sorted(packages.items()):
            if not isinstance(value, list) or not value or not isinstance(value[0], str):
                continue
            name, version = cls.split_spec(value[0])
            if not name:
                continue
            local = version.startswith(cls.LOCAL_PREFIXES)
            remote = version.startswith(cls.REMOTE_PREFIXES)
            registry = value[1] if len(value) > 1 and isinstance(value[1], str) else ""
            metadata = next((v for v in value[1:] if isinstance(v, dict)), {})
            integrity = value[3] if len(value) > 3 and isinstance(value[3], str) else None
            requires: set[str] = set()
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                section = metadata.get(field)
                if isinstance(section, dict):
                    requires.update(str(dep) for dep in section)
            top = "/" not in location.removeprefix(name)
            if top and name in development_only:
                scope = Scope.DEV
            elif top and name in optional_only:
                scope = Scope.OPTIONAL
            else:
                scope = Scope.RUNTIME
            entries.append(
                LockEntry(
                    name=name,
                    version=member_versions.get(name, "") if local else ("" if remote else version),
                    integrity=integrity if integrity and integrity.startswith("sha") else None,
                    resolved_from=version if remote else (registry or None),
                    scope=scope,
                    dependencies=tuple(sorted(requires)),
                    direct=top and name in declared,
                    local=local,
                    platform=NpmEcosystem._platform(metadata),
                )
            )
        return entries


__all__ = ["BunLock"]
