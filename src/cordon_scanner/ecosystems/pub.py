"""Pub: Dart and Flutter.

```
  pubspec.yaml     dependencies, dev_dependencies, dependency_overrides, environment (sdk,
                   flutter), workspace: / resolution: workspace
  pubspec.lock     every resolved package: dependency (direct main | direct dev | direct
                   overridden | transitive), source (hosted | git | path | sdk), version,
                   description (sha256 and url for hosted, resolved-ref for git), sdks
  .dart_tool/package_config.json
                   where `pub get` put each package; repeats the lock's resolution
```

Both YAML files are read with the data-only YAML reader (`core/datayaml.py`).
"""

from __future__ import annotations

import dataclasses
import json
import posixpath
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.datayaml import DataYaml
from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from cordon_scanner.core.content import FileContent


class PubSpec:
    """A pubspec.yaml dependency value as the specification it states."""

    @staticmethod
    def spec(value: Any, directory: str) -> tuple[str, str | None]:
        """`(spec, source)` for `^1.2.0`, `{hosted: ..., version: ...}`, `{git: ...}`,
        `{path: ...}` or `{sdk: flutter}`."""
        if value is None:
            return "any", None
        if isinstance(value, str):
            return value, None
        if not isinstance(value, dict):
            return "*", None
        if "sdk" in value:
            return f"sdk:{value['sdk']}", None
        if "path" in value:
            return f"path:{value['path']}", None
        git = value.get("git")
        if git is not None:
            if isinstance(git, str):
                return f"git+{git}", None
            if isinstance(git, dict):
                url = str(git.get("url", ""))
                reference = git.get("ref")
                return f"git+{url}" + (f"#{reference}" if reference else ""), None
        version = str(value.get("version", "any"))
        hosted = value.get("hosted")
        hosted_url = (
            hosted
            if isinstance(hosted, str)
            else hosted.get("url")
            if isinstance(hosted, dict)
            else None
        )
        return version, (str(hosted_url) if hosted_url else None)


class PubManifest:
    SECTIONS: ClassVar[tuple[tuple[str, Scope], ...]] = (
        ("dependencies", Scope.RUNTIME),
        ("dev_dependencies", Scope.DEV),
    )

    @staticmethod
    def load(content: FileContent) -> dict[str, Any]:
        data = DataYaml.load(content.text, source=content.path)
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ValueError("a pubspec is a mapping")
        return data

    @staticmethod
    def parse(content: FileContent, ecosystem: str, files: Mapping[str, FileContent]) -> Manifest:
        try:
            data = PubManifest.load(content)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid pubspec.yaml: {exc}")
        if "name" not in data:
            return BaseEcosystem._err(content, ecosystem, "a pubspec has no `name`")
        directory = content.path.rpartition("/")[0]
        declared: list[DeclaredDependency] = []
        for section, scope in PubManifest.SECTIONS:
            block = data.get(section)
            if block is not None and not isinstance(block, dict):
                return BaseEcosystem._err(content, ecosystem, f"`{section}` is not a mapping")
            for name, value in sorted((block or {}).items()):
                spec, hosted = PubSpec.spec(value, directory)
                sdk = spec.startswith("sdk:")
                declared.append(
                    DeclaredDependency(
                        name=str(name),
                        spec=spec,
                        # A package that ships with the Dart or Flutter SDK is part of the
                        # platform, not a registry download.
                        scope=Scope.PLATFORM if sdk else scope,
                        field_name=section,
                        source=f"registry:{hosted}" if hosted else None,
                    )
                )
        overrides: dict[str, str] = {}
        for name, value in sorted((data.get("dependency_overrides") or {}).items()):
            overrides[str(name)] = PubSpec.spec(value, directory)[0]
        if "environment" in data and not isinstance(data.get("environment"), dict):
            # pub requires `environment` to be a map holding the SDK constraint. Empty, it is
            # most often a file cut short just after the key, with everything below it lost.
            return BaseEcosystem._err(
                content, ecosystem, "`environment` is not a map of SDK constraints"
            )
        environment = data.get("environment") or {}
        # `platforms:` names the operating systems the package supports; absent, every one. They
        # constrain the package as a whole, so they are recorded on its SDK requirement.
        platforms = data.get("platforms")
        supported = (
            tuple(f"os:{name}" for name in sorted(str(k) for k in platforms))
            if isinstance(platforms, dict)
            else ()
        )
        if isinstance(environment, dict):
            for platform in ("sdk", "flutter"):
                if isinstance(environment.get(platform), str):
                    declared.append(
                        DeclaredDependency(
                            # `flutter-sdk`, not `flutter`: the `flutter` package is a different
                            # record (an SDK package the app depends on).
                            name="dart-sdk" if platform == "sdk" else "flutter-sdk",
                            spec=str(environment[platform]),
                            scope=Scope.PLATFORM,
                            field_name=f"environment.{platform}",
                            platform=supported,
                        )
                    )
        locked_by = None
        if str(data.get("resolution", "")) == "workspace":
            locked_by = PubManifest.workspace_root(content.path, files)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=str(data["name"]),
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
            overrides=overrides,
            locked_by=locked_by,
        )

    @staticmethod
    def workspace_root(path: str, files: Mapping[str, FileContent]) -> str | None:
        """The directory of the pubspec whose `workspace:` lists this member."""
        member = path.rpartition("/")[0]
        directory = member
        for _ in range(32):
            if not directory:
                break
            directory = directory.rpartition("/")[0]
            candidate = f"{directory}/pubspec.yaml" if directory else "pubspec.yaml"
            if candidate in files:
                try:
                    data = PubManifest.load(files[candidate])
                except ValueError:
                    continue
                members = data.get("workspace")
                if isinstance(members, list):
                    listed = {
                        posixpath.normpath(posixpath.join(directory, str(m)))
                        if directory
                        else posixpath.normpath(str(m))
                        for m in members
                    }
                    if member in listed:
                        return directory
        return None


class PubLock:
    """`pubspec.lock` records whether a package is direct, and its source, but no edges: which
    package brought a transitive one in is not in the file. A transitive package is therefore
    graphed as runtime -- the reading that never hides something that may ship -- even when only
    a dev dependency needs it."""

    KINDS: ClassVar[dict[str, Scope]] = {
        "direct main": Scope.RUNTIME,
        "direct dev": Scope.DEV,
        "direct overridden": Scope.RUNTIME,
    }

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid pubspec.lock: {exc}"
            )
        if not isinstance(data, dict) or not isinstance(data.get("packages", {}), dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `packages` mapping"
            )
        entries: list[LockEntry] = []
        for name, meta in sorted((data.get("packages") or {}).items()):
            if not isinstance(meta, dict):
                continue
            kind = str(meta.get("dependency", "transitive"))
            source = str(meta.get("source", "hosted"))
            description = meta.get("description")
            details: dict[str, Any] = description if isinstance(description, dict) else {}
            version = str(meta.get("version", ""))
            resolved_from = None
            integrity = None
            local = False
            scope = PubLock.KINDS.get(kind, Scope.RUNTIME)
            if source == "hosted":
                url = str(details.get("url", ""))
                if url and "pub.dev" not in url and "pub.dartlang.org" not in url:
                    resolved_from = f"registry:{url}"
                sha = details.get("sha256")
                if isinstance(sha, str):
                    integrity = (
                        f"sha256:{sha.lower()}"
                        if re.fullmatch(r"[0-9a-fA-F]{64}", sha)
                        else f"sha256:{sha}"
                    )
            elif source == "git":
                commit = details.get("resolved-ref") or details.get("ref") or ""
                resolved_from = f"git+{details.get('url', '')}#{commit}"
            elif source == "path":
                local = True
            elif source == "sdk":
                scope = Scope.PLATFORM
                resolved_from = f"sdk:{description if isinstance(description, str) else name}"
            entries.append(
                LockEntry(
                    name=str(name),
                    version=version,
                    integrity=integrity,
                    resolved_from=resolved_from,
                    scope=scope,
                    direct=kind.startswith("direct"),
                    local=local,
                )
            )
        sdks = data.get("sdks")
        for platform, constraint in sdks.items() if isinstance(sdks, dict) else ():
            entries.append(
                LockEntry(
                    name=f"{platform}-sdk",
                    version="",
                    scope=Scope.PLATFORM,
                    direct=True,
                    platform=(f"sdk {constraint}",),
                )
            )
        # Pub records a hosted package's sha256 from Dart 2.19; a lock with none at all predates
        # that, and its lack of hashes is its format, not hashes gone missing.
        hosted = [
            e
            for e in entries
            if e.scope is not Scope.PLATFORM and not e.local and not e.resolved_from
        ]
        predates = bool(hosted) and not any(e.integrity for e in hosted)
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            integrity_elsewhere=predates,
        )


class PackageConfig:
    """`.dart_tool/package_config.json`: where each resolved package was put. A companion: the
    lock is the resolution; this repeats it, and is read so it is recognised and checked."""

    HOSTED: ClassVar[re.Pattern[str]] = re.compile(r"/hosted/[^/]+/([\w.\-]+)-(\d[\w.\-+]*)/?$")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        packages = data.get("packages")
        if not isinstance(packages, list):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `packages` list"
            )
        entries = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            found = PackageConfig.HOSTED.search(str(package.get("rootUri", "")))
            if found and found.group(1) == package.get("name"):
                entries.append(LockEntry(name=found.group(1), version=found.group(2)))
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            companion=True,
            owner_levels=1,
            # It records locations, never hashes: those are pubspec.lock's.
            integrity_elsewhere=True,
        )


class PubEcosystem(BaseEcosystem):
    id = "pub"
    purl_type = "pub"
    manifest_globs: tuple[str, ...] = ("**/pubspec.yaml",)
    lockfile_globs: tuple[str, ...] = ("**/pubspec.lock", "**/.dart_tool/package_config.json")
    registry_hosts: frozenset[str] = frozenset({"pub.dev", "pub.dartlang.org"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        return PubManifest.parse(content, self.id, files)

    #: Dart's build hooks: run for every package in the graph when an app that depends on it is
    #: built, unasked, on the building machine. `build.dart` at the package root is the
    #: experimental form that preceded `hook/`.
    BUILD_HOOKS: ClassVar[tuple[str, ...]] = ("hook/build.dart", "hook/link.dart", "build.dart")

    def hooks_from_tree(self, manifest: Manifest, paths: Collection[str]) -> Manifest:
        if manifest.parse_error:
            return manifest
        directory = manifest.path.rpartition("/")[0]
        prefix = f"{directory}/" if directory else ""
        hooks = [
            Hook(
                kind="install",
                path=manifest.path,
                name="install",
                command=f"dart {prefix}{script}",
                ecosystem=self.id,
            )
            for script in PubEcosystem.BUILD_HOOKS
            if f"{prefix}{script}" in paths
        ]
        if not hooks:
            return manifest
        return dataclasses.replace(manifest, hooks=(*manifest.hooks, *hooks))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "package_config.json":
            return PackageConfig.parse(content, self.id)
        return PubLock.parse(content, self.id)


__all__ = ["PackageConfig", "PubEcosystem", "PubLock", "PubManifest", "PubSpec"]
