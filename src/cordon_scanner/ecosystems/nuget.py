"""NuGet / .NET: MSBuild project files read as data, never evaluated.

```
  *.csproj, *.fsproj, *.vbproj   PackageReference, ProjectReference, conditions, properties
  Directory.Build.props          items and properties every project below it inherits
  Directory.Packages.props       central package management: PackageVersion, GlobalPackageReference,
                                 transitive pinning
  packages.config                the pre-PackageReference format
  NuGet.Config                   package sources and package source mapping
  packages.lock.json             what restore resolved, per target framework and runtime identifier
  obj/project.assets.json        what restore resolved, and which packages inject MSBuild code
```

MSBuild is a programming language and its exact answer needs evaluation; what a project file
states literally -- which is what NuGet itself reads for restore -- is read exactly, through the
structural XML reader (`core/safexml.py`), and a condition is kept as the condition it is.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.core.safexml import Element, SafeXml, SafeXmlError
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


@dataclass
class MSBuildItem:
    kind: str
    include: str
    version: str = ""
    version_override: str = ""
    condition: str = ""
    private_assets: str = ""
    include_assets: str = ""
    exclude_assets: str = ""
    line: int = 0


@dataclass
class MSBuildFile:
    """One MSBuild file's properties and items, read without evaluation."""

    path: str
    properties: dict[str, str] = field(default_factory=dict)
    items: list[MSBuildItem] = field(default_factory=list)

    ITEMS: ClassVar[frozenset[str]] = frozenset(
        {
            "PackageReference",
            "PackageVersion",
            "GlobalPackageReference",
            "ProjectReference",
            "PackageDownload",
        }
    )

    @staticmethod
    def read(content: FileContent) -> MSBuildFile:
        root = SafeXml.parse(content.text, source=content.path)
        if root.local != "Project":
            raise SafeXmlError(f"{content.path}: not an MSBuild <Project>")
        found = MSBuildFile(content.path)
        for group in root.children:
            if group.local == "PropertyGroup":
                if group.attributes.get("Condition"):
                    continue  # a conditional property is one value among several; not guessed
                for child in group.children:
                    if not child.attributes.get("Condition"):
                        found.properties[child.local] = child.text.strip()
            elif group.local == "ItemGroup":
                outer = group.attributes.get("Condition", "")
                for child in group.children:
                    if child.local in MSBuildFile.ITEMS:
                        found.items.append(MSBuildFile._item(child, outer))
        found.items = MSBuildFile._apply_updates(found.items)
        return found

    @staticmethod
    def _apply_updates(items: list[MSBuildItem]) -> list[MSBuildItem]:
        """Fold each `Update` item into the items it updates (same kind and name), in order."""
        out: list[MSBuildItem] = []
        for item in items:
            if not item.kind.endswith(":update"):
                out.append(item)
                continue
            kind = item.kind.removesuffix(":update")
            for index, existing in enumerate(out):
                if existing.kind == kind and existing.include.lower() == item.include.lower():
                    out[index] = MSBuildItem(
                        kind=existing.kind,
                        include=existing.include,
                        version=item.version or existing.version,
                        version_override=item.version_override or existing.version_override,
                        condition=existing.condition,
                        private_assets=item.private_assets or existing.private_assets,
                        include_assets=item.include_assets or existing.include_assets,
                        exclude_assets=item.exclude_assets or existing.exclude_assets,
                        line=existing.line,
                    )
        return out

    @staticmethod
    def _item(element: Element, outer: str) -> MSBuildItem:
        def value(name: str) -> str:
            attribute = element.attributes.get(name)
            if attribute is not None:
                return attribute.strip()
            return element.value(name)

        conditions = [c for c in (outer, element.attributes.get("Condition", "")) if c]
        update = element.attributes.get("Update")
        return MSBuildItem(
            # `Update="X"` changes the metadata of an item declared elsewhere; it declares nothing.
            kind=f"{element.local}:update"
            if update is not None and not element.attributes.get("Include")
            else element.local,
            include=(element.attributes.get("Include") or update or "").strip(),
            version=value("Version"),
            version_override=value("VersionOverride"),
            condition=" and ".join(conditions),
            private_assets=value("PrivateAssets"),
            include_assets=value("IncludeAssets"),
            exclude_assets=value("ExcludeAssets"),
            line=element.line,
        )


class MSBuildConditions:
    """A condition kept as the restriction it states: `target framework netstandard2.0`."""

    EQUALS: ClassVar[re.Pattern[str]] = re.compile(
        r"""^\s*'\$\((\w+)\)'\s*==\s*'([^']{0,100})'\s*$"""
    )
    LABELS: ClassVar[dict[str, str]] = {
        "TargetFramework": "target framework",
        "Configuration": "configuration",
        "RuntimeIdentifier": "runtime",
        "Platform": "platform",
        "OS": "os",
    }

    @staticmethod
    def phrase(condition: str) -> tuple[str, ...]:
        if not condition:
            return ()
        out = []
        for part in re.split(r"\s+and\s+", condition, flags=re.IGNORECASE):
            found = MSBuildConditions.EQUALS.match(part)
            if found and found.group(1) in MSBuildConditions.LABELS:
                out.append(f"{MSBuildConditions.LABELS[found.group(1)]} {found.group(2)}")
            else:
                out.append("condition " + " ".join(part.split())[:120])
        return tuple(out)


class MSBuildProperties:
    REFERENCE: ClassVar[re.Pattern[str]] = re.compile(r"\$\(([A-Za-z_][\w.]{0,100})\)")

    @staticmethod
    def expand(value: str, properties: Mapping[str, str]) -> tuple[str, bool]:
        complete = True

        def fill(match: re.Match[str]) -> str:
            nonlocal complete
            if match.group(1) in properties:
                return properties[match.group(1)]
            complete = False
            return match.group(0)

        for _ in range(8):
            expanded = MSBuildProperties.REFERENCE.sub(fill, value)
            if expanded == value:
                break
            value = expanded
        return value, complete

    @staticmethod
    def enabled(properties: Mapping[str, str], name: str) -> bool:
        return properties.get(name, "").strip().lower() == "true"


class NuGetVersions:
    """NuGet's version notation: `1.2.3` is a minimum (`>= 1.2.3`), `[1.2.3]` exact, intervals as
    Maven's, `13.0.*` floating."""

    @staticmethod
    def exact(spec: str) -> str | None:
        text = spec.strip()
        found = re.fullmatch(r"\[\s*([\w.\-+]{1,64})\s*\]", text)
        if found:
            return found.group(1)
        return None

    @staticmethod
    def floating(spec: str) -> bool:
        return "*" in spec


class NuGetConfig:
    """`NuGet.Config`: where packages come from, and which source each package may come from."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            root = SafeXml.parse(content.text, source=content.path)
        except SafeXmlError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable NuGet.Config: {exc}")
        if root.local != "configuration":
            return BaseEcosystem._err(content, ecosystem, "not a NuGet <configuration>")
        sources: list[str] = []
        disabled = {
            e.attributes.get("key", "")
            for e in root.find_all("disabledPackageSources", "add")
            if e.attributes.get("value", "").lower() == "true"
        }
        for element in root.find_all("packageSources", "add"):
            key, value = element.attributes.get("key", ""), element.attributes.get("value", "")
            if key and value and key not in disabled:
                sources.append(f"source {key}: {value}")
        for source in root.find_all("packageSourceMapping", "packageSource"):
            key = source.attributes.get("key", "")
            for package in source.find_all("package"):
                pattern = package.attributes.get("pattern", "")
                if key and pattern:
                    sources.append(f"mapping {key}: {pattern}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class PackagesConfig:
    """`packages.config`: `<package id version targetFramework developmentDependency/>`."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            root = SafeXml.parse(content.text, source=content.path)
        except SafeXmlError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable packages.config: {exc}")
        if root.local != "packages":
            return BaseEcosystem._err(content, ecosystem, "not a <packages> document")
        declared = []
        for package in root.find_all("package"):
            name, version = package.attributes.get("id", ""), package.attributes.get("version", "")
            if not name:
                continue
            framework = package.attributes.get("targetFramework", "")
            development = package.attributes.get("developmentDependency", "").lower() == "true"
            declared.append(
                DeclaredDependency(
                    name=name,
                    # packages.config installs exactly the version it names.
                    spec=f"[{version}]" if version else "*",
                    scope=Scope.DEV if development else Scope.RUNTIME,
                    field_name="packages.config",
                    platform=(f"target framework {framework}",) if framework else (),
                )
            )
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=tuple(declared))


class Frameworks:
    """Target framework names as projects write them (`net8.0`, `netstandard2.0`, `net472`):
    restore files spell the same framework `.NETCoreApp,Version=v8.0`, `.NETStandard,Version=v2.0`,
    `.NETFramework,Version=v4.7.2`."""

    LONG: ClassVar[re.Pattern[str]] = re.compile(
        r"^\.(NETCoreApp|NETStandard|NETFramework),Version=v(\d+)\.(\d+)(?:\.(\d+))?$"
    )

    @staticmethod
    def moniker(name: str) -> str:
        found = Frameworks.LONG.match(name.strip())
        if not found:
            return name.strip()
        family, major, minor, patch = found.groups()
        if family == "NETStandard":
            return f"netstandard{major}.{minor}"
        if family == "NETFramework":
            return f"net{major}{minor}{patch or ''}"
        return f"net{major}.{minor}" if int(major) >= 5 else f"netcoreapp{major}.{minor}"


class NuGetSourceMapping:
    """Package source mapping from the `NuGet.Config` that governs a project: which source each
    package may come from. NuGet matches the longest pattern; `*` matches everything."""

    @staticmethod
    def for_project(path: str, files: Mapping[str, FileContent]) -> dict[str, str]:
        """`pattern -> source` for the nearest NuGet.Config. A source other than nuget.org is
        named as a registry (`registry:acme-local`): a feed -- a server or a folder of .nupkg
        files -- is a package repository, not the package's own source code."""
        config = None
        directory = path.rpartition("/")[0]
        for _ in range(64):
            for name in ("NuGet.Config", "nuget.config", "NuGet.config"):
                candidate = f"{directory}/{name}" if directory else name
                if candidate in files:
                    config = files[candidate]
                    break
            if config is not None or not directory:
                break
            directory = directory.rpartition("/")[0]
        if config is None:
            return {}
        manifest = NuGetConfig.parse(config, "nuget")
        locations = {}
        patterns: dict[str, str] = {}
        for source in manifest.sources:
            kind, _, rest = source.partition(" ")
            key, _, value = rest.partition(": ")
            if kind == "source":
                locations[key] = value
            elif kind == "mapping":
                patterns[value] = key
        return {
            pattern: locations.get(key, "")
            if "nuget.org" in locations.get(key, "").lower()
            else f"registry:{key}"
            for pattern, key in patterns.items()
        }

    @staticmethod
    def source(name: str, mapping: Mapping[str, str]) -> str | None:
        lowered = name.lower()
        best: tuple[int, str] | None = None
        for pattern, location in mapping.items():
            text = pattern.lower()
            matched = lowered == text or (text.endswith("*") and lowered.startswith(text[:-1]))
            if matched and (best is None or len(text) > best[0]):
                best = (len(text), location)
        if best is None or "nuget.org" in best[1]:
            return None
        return best[1]


class NuGetLock:
    """`packages.lock.json`: per target framework (and `<framework>/<runtime>`), each package with
    its type (`Direct`, `Transitive`, `CentralTransitive`, `Project`), resolved version, content
    hash and dependencies. A package in only some frameworks keeps those frameworks as
    conditions; one only in a runtime graph keeps the runtime."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        graphs = data.get("dependencies")
        if not isinstance(graphs, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `dependencies` object"
            )
        frameworks = sorted({Frameworks.moniker(str(k).partition("/")[0]) for k in graphs})
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for key, packages in graphs.items():
            if not isinstance(packages, dict):
                continue
            framework, _, runtime = str(key).partition("/")
            framework = Frameworks.moniker(framework)
            for name, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                kind = str(meta.get("type", "")).lower()
                version = "" if kind == "project" else str(meta.get("resolved", ""))
                slot = merged.setdefault(
                    (str(name), version),
                    {
                        "kinds": set(),
                        "frameworks": set(),
                        "runtimes": set(),
                        "hash": None,
                        "edges": set(),
                        "plain": False,
                    },
                )
                slot["kinds"].add(kind)
                slot["frameworks"].add(framework)
                if runtime:
                    slot["runtimes"].add(runtime)
                else:
                    slot["plain"] = True
                slot["hash"] = slot["hash"] or BaseEcosystem._s(meta.get("contentHash"))
                dependencies = meta.get("dependencies")
                if isinstance(dependencies, dict):
                    slot["edges"].update(str(d) for d in dependencies)
        entries = []
        for (name, version), slot in sorted(merged.items()):
            conditions: list[str] = []
            if set(frameworks) - slot["frameworks"]:
                conditions.extend(f"target framework {f}" for f in sorted(slot["frameworks"]))
            if not slot["plain"]:
                conditions.extend(f"runtime {r}" for r in sorted(slot["runtimes"]))
            local = "project" in slot["kinds"]
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=None if local else slot["hash"],
                    direct="direct" in slot["kinds"],
                    # `"type": "Project"`: another project of the solution, built from source.
                    # No hash, because nothing is fetched.
                    local=local,
                    dependencies=tuple(sorted(slot["edges"])),
                    platform=tuple(conditions),
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class NuGetAssets:
    """`obj/project.assets.json`: restore's full output, written by every `dotnet restore` whether
    or not the project locks. Read as the resolution of the project above `obj/`, and -- as a
    manifest -- for the packages whose `build/` props and targets MSBuild imports into every build
    of the project: code that runs at build time, NuGet's install hook."""

    PLACEHOLDER: ClassVar[str] = "_._"

    @staticmethod
    def load(content: FileContent) -> dict[str, Any]:
        return BaseEcosystem._json_object(content.text)

    @staticmethod
    def lock(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = NuGetAssets.load(content)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        direct: set[str] = set()
        groups = data.get("projectFileDependencyGroups")
        for group in (groups if isinstance(groups, dict) else {}).values():
            if isinstance(group, list):
                direct.update(str(d).split(" ", 1)[0].lower() for d in group)
        targets = data.get("targets")
        target_map = targets if isinstance(targets, dict) else {}
        frameworks = sorted({Frameworks.moniker(str(k).partition("/")[0]) for k in target_map})
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for key, packages in target_map.items():
            if not isinstance(packages, dict):
                continue
            framework, _, runtime = str(key).partition("/")
            framework = Frameworks.moniker(framework)
            for coordinate, meta in packages.items():
                if (
                    not isinstance(meta, dict)
                    or str(meta.get("type", "package")).lower() == "project"
                ):
                    continue
                name, _, version = str(coordinate).partition("/")
                slot = seen.setdefault(
                    (name, version),
                    {"frameworks": set(), "runtimes": set(), "plain": False, "edges": set()},
                )
                slot["frameworks"].add(framework)
                if runtime:
                    slot["runtimes"].add(runtime)
                else:
                    slot["plain"] = True
                dependencies = meta.get("dependencies")
                if isinstance(dependencies, dict):
                    slot["edges"].update(str(d) for d in dependencies)
        libraries = data.get("libraries")
        entries = []
        for coordinate, meta in (libraries if isinstance(libraries, dict) else {}).items():
            if not isinstance(meta, dict) or str(meta.get("type", "package")).lower() == "project":
                continue
            name, _, version = str(coordinate).partition("/")
            if not name:
                continue
            slot = seen.get(
                (name, version),
                {"frameworks": set(frameworks), "runtimes": set(), "plain": True, "edges": set()},
            )
            conditions: list[str] = []
            if set(frameworks) - slot["frameworks"]:
                conditions.extend(f"target framework {f}" for f in sorted(slot["frameworks"]))
            if not slot["plain"]:
                conditions.extend(f"runtime {r}" for r in sorted(slot["runtimes"]))
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=BaseEcosystem._s(meta.get("sha512")),
                    dependencies=tuple(sorted(slot["edges"])),
                    direct=name.lower() in direct,
                    platform=tuple(conditions),
                )
            )
        return LockGraph(
            path=content.path, ecosystem=ecosystem, entries=tuple(entries), owner_levels=1
        )

    @staticmethod
    def hooks(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = NuGetAssets.load(content)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        found: dict[str, set[str]] = {}
        targets = data.get("targets")
        for packages in (targets if isinstance(targets, dict) else {}).values():
            if not isinstance(packages, dict):
                continue
            for coordinate, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                for key in ("build", "buildMultiTargeting"):
                    files = meta.get(key)
                    for file in files if isinstance(files, dict) else {}:
                        if not str(file).endswith(NuGetAssets.PLACEHOLDER):
                            found.setdefault(str(coordinate).partition("/")[0], set()).add(
                                str(file)
                            )
        hooks = tuple(
            Hook(
                kind="build",
                path=content.path,
                name=name,
                command="msbuild imports " + ", ".join(sorted(files)[:4]),
                ecosystem=ecosystem,
            )
            for name, files in sorted(found.items())
        )
        return Manifest(path=content.path, ecosystem=ecosystem, hooks=hooks)


class NuGetEcosystem(BaseEcosystem):
    id = "nuget"
    purl_type = "nuget"
    manifest_globs: tuple[str, ...] = (
        "**/*.csproj",
        "**/*.fsproj",
        "**/*.vbproj",
        "**/packages.config",
        "**/Directory.Packages.props",
        "**/Directory.Build.props",
        "**/NuGet.Config",
        "**/nuget.config",
        "**/NuGet.config",
        "**/obj/project.assets.json",
    )
    lockfile_globs: tuple[str, ...] = ("**/packages.lock.json", "**/project.assets.json")
    registry_hosts: frozenset[str] = frozenset({"api.nuget.org", "nuget.org", "www.nuget.org"})

    PROJECT_SUFFIXES: ClassVar[tuple[str, ...]] = (".csproj", ".fsproj", ".vbproj")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    @staticmethod
    def _nearest(path: str, name: str, files: Mapping[str, FileContent]) -> FileContent | None:
        """The `name` MSBuild imports for this file: the nearest one at or above its directory,
        the way `Directory.Build.props` and `Directory.Packages.props` are found."""
        directory = path.rpartition("/")[0]
        for _ in range(64):
            candidate = f"{directory}/{name}" if directory else name
            if candidate in files and candidate != path:
                return files[candidate]
            if not directory:
                return None
            directory = directory.rpartition("/")[0]
        return None

    @staticmethod
    def _read(content: FileContent | None) -> MSBuildFile | None:
        if content is None:
            return None
        try:
            return MSBuildFile.read(content)
        except SafeXmlError:
            return None

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        name = content.basename
        lowered = name.lower()
        if lowered == "nuget.config":
            return NuGetConfig.parse(content, self.id)
        if lowered == "packages.config":
            return PackagesConfig.parse(content, self.id)
        if lowered == "project.assets.json":
            return NuGetAssets.hooks(content, self.id)
        try:
            own = MSBuildFile.read(content)
        except SafeXmlError as exc:
            return BaseEcosystem._err(content, self.id, f"not a readable MSBuild file: {exc}")
        if name == "Directory.Packages.props":
            return self._central(own, content, files)
        if name == "Directory.Build.props":
            # Its items belong to every project below it, and are recorded against each of them.
            return Manifest(path=content.path, ecosystem=self.id)
        build = self._read(self._nearest(content.path, "Directory.Build.props", files))
        central = self._read(self._nearest(content.path, "Directory.Packages.props", files))
        properties: dict[str, str] = {}
        for layer in (build, central, own):
            if layer is not None:
                properties.update(layer.properties)
        managed = (
            MSBuildProperties.enabled(properties, "ManagePackageVersionsCentrally")
            and central is not None
        )
        central_versions = {
            item.include: MSBuildProperties.expand(item.version, properties)[0]
            for item in (central.items if central else [])
            if item.kind == "PackageVersion" and item.include
        }
        versions = {name.lower(): version for name, version in central_versions.items()}
        pinning = managed and MSBuildProperties.enabled(
            properties, "CentralPackageTransitivePinningEnabled"
        )
        central_path = central.path if central else None
        mapping = NuGetSourceMapping.for_project(content.path, files)
        test_project = MSBuildProperties.enabled(properties, "IsTestProject") or any(
            i.include == "Microsoft.NET.Test.Sdk" for i in own.items if i.kind == "PackageReference"
        )
        declared: list[DeclaredDependency] = []
        layers: list[tuple[MSBuildFile, str]] = []
        if build is not None:
            layers.append((build, " (Directory.Build.props)"))
        layers.append((own, ""))
        for layer, origin in layers:
            for item in layer.items:
                if item.kind == "ProjectReference":
                    target = posixpath.normpath(
                        posixpath.join(
                            posixpath.dirname(layer.path), item.include.replace("\\", "/")
                        )
                    )
                    here = content.path.rpartition("/")[0] or "."
                    stem = posixpath.basename(target)
                    for suffix in self.PROJECT_SUFFIXES:
                        stem = stem.removesuffix(suffix)
                    declared.append(
                        DeclaredDependency(
                            name=stem.lower(),
                            spec=f"path:{posixpath.relpath(posixpath.dirname(target) or '.', here)}",
                            field_name="ProjectReference" + origin,
                            platform=MSBuildConditions.phrase(item.condition),
                        )
                    )
                    continue
                if item.kind not in ("PackageReference", "PackageDownload") or not item.include:
                    continue
                reference = self._reference(
                    item, origin, properties, managed, versions, test_project
                )
                mapped = NuGetSourceMapping.source(item.include, mapping)
                if mapped:
                    # Source mapping routes it to a feed other than nuget.org.
                    reference = DeclaredDependency(
                        name=reference.name,
                        spec=reference.spec,
                        scope=reference.scope,
                        field_name=reference.field_name,
                        platform=reference.platform,
                        note=reference.note,
                        source=mapped,
                    )
                declared.append(reference)
        if central is not None and managed:
            for item in central.items:
                if item.kind == "GlobalPackageReference" and item.include:
                    version, _ = MSBuildProperties.expand(item.version, properties)
                    declared.append(
                        DeclaredDependency(
                            name=item.include,
                            spec=version or "*",
                            # Global references are build tooling by definition: NuGet adds them
                            # to every project with all assets private.
                            scope=Scope.BUILD,
                            field_name="GlobalPackageReference (Directory.Packages.props)",
                            platform=MSBuildConditions.phrase(item.condition),
                        )
                    )
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=properties.get("PackageId") or None,
            version=properties.get("Version") or None,
            dependencies=tuple(declared),
            source_patterns={p: s for p, s in mapping.items() if "nuget.org" not in s.lower()},
            # Transitive pinning: every central version also pins the packages this project
            # only reaches transitively. One it references directly simply uses the version.
            overrides={
                name: version
                for name, version in central_versions.items()
                if pinning and version and name.lower() not in {d.name.lower() for d in declared}
            },
            override_origin=central_path if pinning else None,
        )

    def _reference(
        self,
        item: MSBuildItem,
        origin: str,
        properties: Mapping[str, str],
        managed: bool,
        versions: Mapping[str, str],
        test_project: bool,
    ) -> DeclaredDependency:
        note = None
        if item.version_override:
            spec, complete = MSBuildProperties.expand(item.version_override, properties)
        elif item.version:
            spec, complete = MSBuildProperties.expand(item.version, properties)
        elif managed:
            spec, complete = versions.get(item.include.lower(), ""), True
            if not spec:
                note = "central package management is on and Directory.Packages.props has no PackageVersion for it"
        else:
            spec, complete = "", True
            note = "no version is declared"
        if not complete:
            note = "the version uses an MSBuild property no file in the scanned tree defines"
            spec = ""
        assets = (item.include_assets or "").lower()
        excluded = (item.exclude_assets or "").lower()
        build_only = (assets and not any(a in assets for a in ("runtime", "compile", "all"))) or (
            "runtime" in excluded and "compile" in excluded
        )
        scope = (
            Scope.TEST
            if test_project
            else Scope.BUILD
            if build_only or item.kind == "PackageDownload"
            else Scope.RUNTIME
        )
        return DeclaredDependency(
            name=item.include,
            spec=spec or "*",
            scope=scope,
            field_name=item.kind + origin + (" VersionOverride" if item.version_override else ""),
            platform=MSBuildConditions.phrase(item.condition),
            note=note,
        )

    def _central(
        self, own: MSBuildFile, content: FileContent, files: Mapping[str, FileContent]
    ) -> Manifest:
        """`Directory.Packages.props`: the versions every project's references take. It declares
        nothing itself; each project below it carries what it contributes (its versions, its
        global references, and with transitive pinning its pins)."""
        properties = dict(own.properties)
        build = self._read(self._nearest(content.path, "Directory.Build.props", files))
        if build is not None:
            properties = {**build.properties, **properties}
        versions = {
            item.include: MSBuildProperties.expand(item.version, properties)[0]
            for item in own.items
            if item.kind == "PackageVersion" and item.include
        }
        return Manifest(path=content.path, ecosystem=self.id, shared_specs=versions)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "project.assets.json":
            return NuGetAssets.lock(content, self.id)
        return NuGetLock.parse(content, self.id)


__all__ = [
    "MSBuildFile",
    "NuGetAssets",
    "NuGetConfig",
    "NuGetEcosystem",
    "NuGetLock",
    "PackagesConfig",
]
