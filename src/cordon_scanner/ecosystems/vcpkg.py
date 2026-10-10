"""vcpkg (C and C++), manifest mode.

```
  vcpkg.json                dependencies (a name, or an object with features, default-features,
                            host, platform, version>=), features (optional groups with their own
                            dependencies), overrides (exact versions), builtin-baseline, supports;
                            an embedded "vcpkg-configuration"
  vcpkg-configuration.json  the default registry (builtin, git, filesystem) and its baseline,
                            further registries with the package patterns they serve, overlay
                            ports and triplets
  vcpkg-lock.json           the commit each git registry's reference resolved to
  ports/<port>/             an overlay port: the project's own vcpkg.json and portfile.cmake
```

vcpkg resolves a version from a registry's version database at the baseline commit: the minimum
satisfying every `version>=` and the baseline, unless an override names one exactly. The
repository holds the baseline, not the database, so without an override a version is not known
here -- that is stated rather than guessed.
"""

from __future__ import annotations

import dataclasses
import json
import posixpath
import re
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from cordon_scanner.core.content import FileContent


VERSION_FIELDS = ("version", "version-semver", "version-date", "version-string")
PORT_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class VcpkgFields:
    """Readings shared by vcpkg.json and its lock."""

    @staticmethod
    def version_of(data: Mapping[str, Any]) -> str | None:
        for key in VERSION_FIELDS:
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return None


class VcpkgConfiguration:
    """Registries and overlays, from vcpkg-configuration.json or vcpkg.json's embedded copy."""

    @staticmethod
    def read(data: Mapping[str, Any]) -> tuple[list[str], dict[str, str], str | None]:
        """`(sources, package pattern -> source, default registry's baseline)`."""
        sources: list[str] = []
        routed: dict[str, str] = {}
        baseline: str | None = None
        default = data.get("default-registry")
        if isinstance(default, dict):
            kind = str(default.get("kind", ""))
            baseline = BaseEcosystem._s(default.get("baseline"))
            location = VcpkgConfiguration.location(default)
            sources.append(
                f"default registry {kind}"
                + (f" {location}" if location else "")
                + (f" (baseline {baseline})" if baseline else "")
            )
            if kind != "builtin" and location:
                routed["*"] = location
        elif default is None and "default-registry" in data:
            # `"default-registry": null`: only the named registries resolve anything.
            sources.append("default registry disabled")
        registries = data.get("registries")
        for registry in registries if isinstance(registries, list) else []:
            if not isinstance(registry, dict):
                continue
            location = VcpkgConfiguration.location(registry)
            patterns = [str(p) for p in registry.get("packages") or [] if isinstance(p, str)]
            sources.append(
                f"registry {registry.get('kind', '')} {location or ''} for {', '.join(patterns) or 'nothing'}".replace(
                    "  ", " "
                )
            )
            for pattern in patterns:
                if location:
                    routed[pattern] = location
        for key in ("overlay-ports", "overlay-triplets"):
            listed = data.get(key)
            if isinstance(listed, list) and listed:
                sources.append(f"{key.replace('-', ' ')} {', '.join(str(p) for p in listed)}")
        return sources, routed, baseline

    @staticmethod
    def location(registry: Mapping[str, Any]) -> str | None:
        kind = registry.get("kind")
        if kind == "git" and isinstance(registry.get("repository"), str):
            baseline = registry.get("baseline")
            return f"git+{registry['repository']}" + (
                f"#{baseline}" if isinstance(baseline, str) else ""
            )
        if kind == "filesystem" and isinstance(registry.get("path"), str):
            return f"path:{registry['path']}"
        if kind == "artifact" and isinstance(registry.get("location"), str):
            return str(registry["location"])
        return None

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        sources, routed, _baseline = VcpkgConfiguration.read(data)
        return Manifest(
            path=content.path, ecosystem=ecosystem, sources=tuple(sources), source_patterns=routed
        )


class VcpkgManifest:
    """vcpkg.json."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str, files: Mapping[str, FileContent]) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            return BaseEcosystem._err(content, ecosystem, "`dependencies` is not a list")
        overrides = {
            str(o["name"]): VcpkgFields.version_of(o) or ""
            for o in data.get("overrides") or []
            if isinstance(o, dict) and isinstance(o.get("name"), str)
        }
        # A port-version is a revision of the port (its build scripts), not of the library: the
        # library version is what advisories name, and the port revision is carried beside it.
        revisions = {
            str(o["name"]): f"port-version {o['port-version']}"
            for o in data.get("overrides") or []
            if isinstance(o, dict)
            and isinstance(o.get("name"), str)
            and isinstance(o.get("port-version"), int)
            and o["port-version"] > 0
        }
        embedded = data.get("vcpkg-configuration")
        configuration: Mapping[str, Any] = embedded if isinstance(embedded, dict) else {}
        directory = content.path.rpartition("/")[0]
        beside = (
            f"{directory}/vcpkg-configuration.json" if directory else "vcpkg-configuration.json"
        )
        if not configuration and beside in files:
            try:
                configuration = BaseEcosystem._json_object(files[beside].text)
            except (json.JSONDecodeError, ValueError):
                configuration = {}
        read, routed, registry_baseline = VcpkgConfiguration.read(configuration)
        # A separate vcpkg-configuration.json reports its own sources; an embedded one is this
        # file's. Its routing applies to this manifest's ports either way.
        sources = list(read) if embedded else []
        baseline = (
            BaseEcosystem._s(data.get("builtin-baseline"))
            or registry_baseline
            or VcpkgManifest.inherited(content.path, files)
        )
        if isinstance(data.get("builtin-baseline"), str):
            sources.insert(0, f"builtin-baseline {data['builtin-baseline']}")
        supports = data.get("supports")
        if isinstance(supports, str):
            sources.append(f"supports {supports}")
        unresolved = (
            f"resolved from the registry's version database at baseline {baseline}, which the repository does not hold"
            if baseline
            else "resolved from whatever registry checkout builds it: no baseline pins the versions"
        )
        declared: list[DeclaredDependency] = []
        default_features = {
            str(f if isinstance(f, str) else f.get("name"))
            for f in data.get("default-features") or []
            if isinstance(f, (str, dict))
        }
        for entry in dependencies:
            dependency = VcpkgManifest.dependency(
                entry, Scope.RUNTIME, "dependencies", overrides, unresolved, (), revisions
            )
            if dependency is None:
                return BaseEcosystem._err(
                    content,
                    ecosystem,
                    "a dependency that is not a port name or a dependency object",
                )
            declared.append(dependency)
        features = data.get("features")
        for feature, body in features.items() if isinstance(features, dict) else []:
            listed = body.get("dependencies") if isinstance(body, dict) else None
            for entry in listed if isinstance(listed, list) else []:
                on = feature in default_features
                dependency = VcpkgManifest.dependency(
                    entry,
                    Scope.RUNTIME if on else Scope.OPTIONAL,
                    f"features.{feature}",
                    overrides,
                    unresolved
                    if on
                    else f"a dependency of the optional feature `{feature}`: installed only when the feature is asked for",
                    (f"feature {feature}",),
                    revisions,
                )
                if dependency is not None:
                    declared.append(dependency)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(data.get("name")),
            version=VcpkgFields.version_of(data),
            dependencies=tuple(declared),
            overrides={name: version for name, version in overrides.items() if version},
            sources=tuple(sources),
            source_patterns=routed,
        )

    @staticmethod
    def inherited(path: str, files: Mapping[str, FileContent]) -> str | None:
        """The baseline of the project above a port's own vcpkg.json (an overlay port in its
        `ports/` directory): the project's registry resolves the port's dependencies."""
        directory = path.rpartition("/")[0]
        while directory:
            directory = directory.rpartition("/")[0]
            candidate = files.get(f"{directory}/vcpkg.json" if directory else "vcpkg.json")
            if candidate is None:
                continue
            try:
                above = BaseEcosystem._json_object(candidate.text)
            except (json.JSONDecodeError, ValueError):
                return None
            return BaseEcosystem._s(above.get("builtin-baseline"))
        return None

    @staticmethod
    def dependency(
        entry: object,
        scope: Scope,
        field_name: str,
        overrides: Mapping[str, str],
        unresolved: str,
        conditions: tuple[str, ...],
        revisions: Mapping[str, str],
    ) -> DeclaredDependency | None:
        if isinstance(entry, str):
            name, body = entry, {}
        elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
            name, body = entry["name"], entry
        else:
            return None
        if not PORT_NAME.match(name):
            return None
        features = [
            str(f if isinstance(f, str) else f.get("name"))
            for f in body.get("features") or []
            if isinstance(f, str) or (isinstance(f, dict) and isinstance(f.get("name"), str))
        ]
        if body.get("default-features") is False:
            features.insert(0, "core")
        platform = (
            *conditions,
            *([body["platform"]] if isinstance(body.get("platform"), str) else []),
            *([revisions[name]] if name in revisions else []),
        )
        override = overrides.get(name)
        minimum = body.get("version>=")
        if override:
            spec = override
        elif isinstance(minimum, str):
            spec = f">={minimum}"
        else:
            spec = "*"
        # A host dependency is built for the machine running the build: a tool (vcpkg-cmake, a
        # code generator), not something linked into the product.
        return DeclaredDependency(
            name=name,
            spec=spec,
            scope=Scope.TOOL if body.get("host") is True else scope,
            field_name=field_name,
            platform=platform,
            extras=tuple(features),
            # A pinned port still comes from the version database at the baseline, which is what
            # names its files (and so its upstream source); unpinned, it is what resolves it.
            note=(
                f"pinned by an override; vcpkg reads the port at baseline {at.group(1)}"
                if (at := re.search(r"\bat baseline ([0-9a-f]{40})\b", unresolved or ""))
                else None
            )
            if override
            else unresolved,
        )


class VcpkgLock:
    """vcpkg-lock.json: the commit each git registry's reference resolved to. It pins registries,
    not ports."""

    @staticmethod
    def sources(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        out: list[str] = []
        for repository, references in sorted(data.items()):
            if not isinstance(references, dict):
                return BaseEcosystem._err(
                    content,
                    ecosystem,
                    "a registry entry that is not a map of references to commits",
                )
            for reference, commit in sorted(references.items()):
                if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                    return BaseEcosystem._err(
                        content, ecosystem, "a registry reference not locked to a commit"
                    )
                out.append(f"registry {repository} {reference} locked at {commit}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(out))


class VcpkgEcosystem(BaseEcosystem):
    """C and C++ ports through vcpkg's manifest mode."""

    id = "vcpkg"
    purl_type = "vcpkg"
    manifest_globs: tuple[str, ...] = (
        "**/vcpkg.json",
        "**/vcpkg-configuration.json",
        "**/vcpkg-lock.json",
    )
    lockfile_globs: tuple[str, ...] = ("**/vcpkg-lock.json",)
    registry_hosts: frozenset[str] = frozenset({"github.com/microsoft/vcpkg"})
    records_integrity = False
    """No vcpkg file records a port's hash: each version is pinned by git-tree in the registry's
    version database, at the baseline commit."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def hooks_from_tree(self, manifest: Manifest, paths: Collection[str]) -> Manifest:
        """A custom triplet is CMake run for every port it builds -- compiler flags, toolchains,
        whatever the file does. The triplet files in the overlay-triplets directories a
        configuration names are recorded as build hooks, as a Bazel module extension is."""
        if manifest.parse_error:
            return manifest
        base = manifest.path.rpartition("/")[0]
        directories: list[str] = []
        for source in manifest.sources:
            if source.startswith("overlay triplets "):
                directories.extend(source.removeprefix("overlay triplets ").split(", "))
        hooks = []
        for directory in directories:
            root = posixpath.normpath(posixpath.join(base, directory) if base else directory)
            for path in sorted(paths):
                if path.startswith(f"{root}/") and path.endswith(".cmake"):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=manifest.path,
                            name=f"triplet {posixpath.basename(path).removesuffix('.cmake')}",
                            command=path,
                            ecosystem=self.id,
                        )
                    )
        if not hooks:
            return manifest
        return dataclasses.replace(manifest, hooks=(*manifest.hooks, *hooks))

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        basename = content.basename
        if basename == "vcpkg-configuration.json":
            return VcpkgConfiguration.parse(content, self.id)
        if basename == "vcpkg-lock.json":
            return VcpkgLock.sources(content, self.id)
        return VcpkgManifest.parse(content, self.id, files)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        """vcpkg-lock.json locks registries, so it resolves no port; read for its errors only."""
        manifest = VcpkgLock.sources(content, self.id)
        return LockGraph(path=content.path, ecosystem=self.id, parse_error=manifest.parse_error)


__all__ = ["VcpkgConfiguration", "VcpkgEcosystem", "VcpkgFields", "VcpkgLock", "VcpkgManifest"]
