"""Stack: stack.yaml's resolver and extra dependencies, and stack.yaml.lock's pinned packages."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.foundation.formats.datayaml import DataYaml
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.foundation.content import FileContent


class StackProject:
    """stack.yaml."""

    HACKAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*?)-([0-9]+(?:\.[0-9]+)*)(?:@(rev:[0-9]+|sha256:[0-9a-f]{64}(?:,[0-9]+)?))?$"
    )

    @staticmethod
    def load(content: FileContent) -> dict[str, Any]:
        data = DataYaml.load(content.text, source=content.path)
        if not isinstance(data, dict):
            raise ValueError("not a mapping")
        return data

    @staticmethod
    def snapshot(data: Mapping[str, Any]) -> str | None:
        value = data.get("snapshot", data.get("resolver"))
        if isinstance(value, dict):
            value = value.get("url")
        return str(value) if value else None

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = StackProject.load(content)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid stack.yaml: {exc}")
        snapshot = StackProject.snapshot(data)
        if not snapshot:
            return BaseEcosystem._err(
                content, ecosystem, "a stack.yaml without a snapshot (`snapshot` or `resolver`)"
            )
        sources = [f"snapshot {snapshot}"]
        overrides: dict[str, str] = {}
        routed: dict[str, str] = {}
        declared: list[DeclaredDependency] = []
        extra = data.get("extra-deps")
        for item in extra if isinstance(extra, list) else []:
            if isinstance(item, str):
                pinned = StackProject.HACKAGE.match(item.strip())
                if pinned:
                    overrides[pinned.group(1)] = f"=={pinned.group(2)}"
                    if pinned.group(3):
                        sources.append(
                            f"extra-dep {pinned.group(1)}-{pinned.group(2)} pinned to {pinned.group(3).split(',')[0]}"
                        )
                elif item.startswith(("http://", "https://")):
                    name = re.sub(r"(?:\.tar\.gz|\.zip|\.tgz)$", "", item.rpartition("/")[2])
                    routed[re.sub(r"-[0-9][0-9.]*$", "", name)] = item
                continue
            if not isinstance(item, dict):
                continue
            location = item.get("git") or (
                f"https://github.com/{item['github']}"
                if isinstance(item.get("github"), str)
                else None
            )
            if isinstance(location, str):
                commit = BaseEcosystem._s(item.get("commit")) or ""
                listed = item.get("subdirs")
                subdirs: list[Any] = listed if isinstance(listed, list) else []
                repo = location.rstrip("/").rpartition("/")[2].removesuffix(".git")
                for name in [str(s).rstrip("/").rpartition("/")[2] for s in subdirs] or [repo]:
                    routed[name] = f"git+{location}#{commit}" if commit else f"git+{location}"
            elif isinstance(item.get("url"), str):
                name = re.sub(r"(?:\.tar\.gz|\.zip|\.tgz)$", "", item["url"].rpartition("/")[2])
                routed[re.sub(r"-[0-9][0-9.]*$", "", name)] = item["url"]
        flags = data.get("flags")
        if isinstance(flags, dict):
            for package, assigned in sorted(flags.items()):
                if isinstance(assigned, dict):
                    text = " ".join(
                        f"{'+' if v is True else '-'}{k}" for k, v in sorted(assigned.items())
                    )
                    sources.append(f"flags {package}: {text}")
        compiler = data.get("compiler")
        if isinstance(compiler, str):
            found = re.match(r"^(ghc|ghcjs)-([0-9][0-9.]*)$", compiler)
            declared.append(
                DeclaredDependency(
                    name=found.group(1) if found else "ghc",
                    spec=found.group(2) if found else compiler,
                    scope=Scope.PLATFORM,
                    field_name="compiler",
                )
            )
        indices = data.get("package-indices") or (
            [data["package-index"]] if isinstance(data.get("package-index"), dict) else []
        )
        for index in indices if isinstance(indices, list) else []:
            if isinstance(index, dict):
                url = index.get("download-prefix") or index.get("http")
                sources.append(
                    f"repository {index.get('name', 'package-index')} {url or ''}".strip()
                )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            overrides=overrides,
            sources=tuple(sources),
            source_patterns=routed,
        )


class StackLock:
    """stack.yaml.lock: the extra-deps completed, and the snapshot by hash."""

    HACKAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*?)-([0-9]+(?:\.[0-9]+)*)(?:@sha256:([^,\s]+),[0-9]+)?$"
    )
    """`name-version@sha256:<cabal-file hash>,<size>`. A hash that is not 64 hex digits is kept
    and judged malformed, not read as a damaged file."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = StackProject.load(content)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid stack.yaml.lock: {exc}",
            )
        if "snapshots" not in data:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a stack.yaml.lock without `snapshots`",
            )
        listed = data.get("packages", data.get("dependencies")) or []
        if not isinstance(listed, list):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="`packages` is not a list"
            )
        entries: list[LockEntry] = []
        for item in listed:
            completed = item.get("completed") if isinstance(item, dict) else None
            if not isinstance(completed, dict):
                continue
            if isinstance(completed.get("hackage"), str):
                found = StackLock.HACKAGE.match(completed["hackage"].strip())
                if not found:
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error="a Hackage entry that is not `name-version@sha256:<hash>,<size>`",
                    )
                # The SHA-256 of the pinned cabal-file revision: what Hackage lists per revision.
                digest = found.group(3)
                entries.append(
                    LockEntry(
                        name=found.group(1),
                        version=found.group(2),
                        integrity=f"sha256:{digest.lower()}" if digest else None,
                    )
                )
                continue
            name = BaseEcosystem._s(completed.get("name"))
            version = BaseEcosystem._s(completed.get("version"))
            if not name or not version:
                continue
            location = completed.get("git") or (
                f"https://github.com/{completed['github']}"
                if isinstance(completed.get("github"), str)
                else None
            )
            if isinstance(location, str):
                entries.append(
                    LockEntry(
                        name=name,
                        version=version,
                        resolved_from=f"git+{location}#{completed.get('commit', '')}",
                    )
                )
            elif isinstance(completed.get("url"), str):
                digest = BaseEcosystem._s(completed.get("sha256"))
                entries.append(
                    LockEntry(
                        name=name,
                        version=version,
                        resolved_from=completed["url"],
                        integrity=f"sha256:{digest}" if digest else None,
                    )
                )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


__all__ = ["StackLock", "StackProject"]
