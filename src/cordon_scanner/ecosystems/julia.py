"""Julia: Project.toml, Manifest.toml and Artifacts.toml.

```
  Project.toml        [deps] name = uuid; [weakdeps] and the [extensions] they enable; [extras]
                      with [targets] (test-only dependencies, the pre-1.9 form); [compat] bounds,
                      `julia` among them; [sources] (1.11+: url / rev / subdir, or path);
                      [workspace] projects (1.12+), which share the root's manifest
  Manifest.toml       the resolution. Format 1 (Julia <= 1.6) keeps `[[Name]]` at the top level;
  JuliaManifest.toml  format 2 (1.7+) nests them under `[[deps.Name]]` beside `julia_version`.
  Manifest-v1.11.toml Each entry: uuid, version, git-tree-sha1 (the tree Pkg verifies), repo-url
                      and repo-rev (git), path (developed in place), deps, weakdeps
  Artifacts.toml      binaries Pkg downloads per platform (os, arch, libc), each named by the
                      git-tree-sha1 of its content, with download URLs and their sha256
```

A Julia package is its UUID, not its name: two registries can each hold a `Foo`, and the manifest
names which by UUID. The UUID is carried as the purl's `uuid` qualifier (the purl-spec form).

A standard library (`Dates`, `Printf`, ...) ships with Julia: no tree hash, no download.
"""

from __future__ import annotations

import dataclasses
import re
import tomllib
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Scope
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


UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class JuliaToml:
    """Readings of Project.toml and Manifest.toml shared by the parsers below."""

    @staticmethod
    def identity(uuid: Any) -> tuple[str, ...]:
        """The record condition carrying a package's UUID, read back by `qualifiers`."""
        return (f"uuid {str(uuid).lower()}",) if isinstance(uuid, str) and UUID.match(uuid) else ()

    @staticmethod
    def table(data: Mapping[str, Any], key: str) -> dict[str, Any]:
        """A TOML table of the document, or an empty one when the key holds anything else."""
        value = data.get(key)
        return value if isinstance(value, dict) else {}


class Project:
    """Project.toml (and JuliaProject.toml)."""

    @staticmethod
    def load(content: FileContent) -> dict[str, Any]:
        return tomllib.loads(content.text)

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = Project.load(content)
        except tomllib.TOMLDecodeError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid TOML: {exc}")
        deps = JuliaToml.table(data, "deps")
        weak = JuliaToml.table(data, "weakdeps")
        extras = JuliaToml.table(data, "extras")
        compat = JuliaToml.table(data, "compat")
        sources = JuliaToml.table(data, "sources")
        targets = JuliaToml.table(data, "targets")
        extensions = JuliaToml.table(data, "extensions")
        for section, value in (("deps", deps), ("weakdeps", weak), ("extras", extras)):
            for uuid in value.values():
                if not isinstance(uuid, str) or not UUID.match(uuid):
                    # A dependency is named by UUID; without one Pkg cannot resolve it.
                    return BaseEcosystem._err(
                        content, ecosystem, f"a [{section}] entry whose value is not a UUID"
                    )
        enables: dict[str, list[str]] = {}
        for extension, triggers in extensions.items():
            for trigger in triggers if isinstance(triggers, list) else [triggers]:
                enables.setdefault(str(trigger), []).append(str(extension))
        test_only = (
            {str(n) for n in targets.get("test", []) if isinstance(n, str)}
            if isinstance(targets.get("test"), list)
            else set()
        )
        declared: list[DeclaredDependency] = []

        def spec(name: str) -> tuple[str, str | None]:
            source = sources.get(name)
            if isinstance(source, dict):
                if isinstance(source.get("url"), str):
                    rev = source.get("rev")
                    return f"git+{source['url']}" + (
                        f"#{rev}" if isinstance(rev, str) else ""
                    ), None
                if isinstance(source.get("path"), str):
                    return f"path:{source['path']}", None
            bound = compat.get(name)
            return (str(bound) if isinstance(bound, str) else "*"), None

        for name, uuid in deps.items():
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.RUNTIME,
                    field_name="deps",
                    platform=JuliaToml.identity(uuid),
                )
            )
        for name, uuid in weak.items():
            unlocks = ", ".join(sorted(enables.get(name, []))) or "no extension"
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.OPTIONAL,
                    field_name="weakdeps",
                    platform=JuliaToml.identity(uuid),
                    note=f"a weak dependency: installed only by a user who adds it, which loads {unlocks}",
                )
            )
        for name, uuid in extras.items():
            if name in deps or name in weak:
                continue
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.TEST if name in test_only else Scope.DEV,
                    field_name="extras",
                    platform=JuliaToml.identity(uuid),
                    note="a test-only dependency ([extras] and [targets]): resolved when the tests run, not into the manifest",
                )
            )
        julia = compat.get("julia")
        if isinstance(julia, str):
            declared.append(
                DeclaredDependency(
                    name="julia", spec=julia, scope=Scope.PLATFORM, field_name="compat"
                )
            )
        notes = [
            f"extension {ext} (loaded with {', '.join(str(t) for t in (trig if isinstance(trig, list) else [trig]))})"
            for ext, trig in sorted(extensions.items())
        ]
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(data.get("name")),
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
            sources=tuple(notes),
            repository=None,
        )

    @staticmethod
    def workspace_root(path: str, files: Mapping[str, FileContent]) -> str | None:
        """The directory of the Project.toml above this one whose `[workspace] projects` lists
        it: the workspace whose single manifest resolves it (Julia 1.12+)."""
        own = path.rpartition("/")[0]
        directory = own
        while directory:
            directory = directory.rpartition("/")[0]
            candidate = f"{directory}/Project.toml" if directory else "Project.toml"
            if candidate not in files:
                continue
            try:
                data = Project.load(files[candidate])
            except tomllib.TOMLDecodeError:
                return None
            workspace = data.get("workspace")
            projects = workspace.get("projects") if isinstance(workspace, dict) else None
            relative = own[len(directory) + 1 :] if directory else own
            if isinstance(projects, list) and relative in {
                str(p).removeprefix("./").rstrip("/") for p in projects
            }:
                return directory
        return None


class JuliaManifest:
    """Manifest.toml, formats 1 and 2."""

    FORMATS: ClassVar[frozenset[str]] = frozenset({"2.0"})

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = tomllib.loads(content.text)
        except tomllib.TOMLDecodeError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid TOML: {exc}"
            )
        declared_format = data.get("manifest_format")
        if declared_format is not None:
            if str(declared_format) not in JuliaManifest.FORMATS:
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a manifest_format this reader does not know",
                )
            packages = JuliaToml.table(data, "deps")
        else:
            # Format 1: every top-level array of tables is a package.
            packages = {k: v for k, v in data.items() if isinstance(v, list)}
        entries: list[LockEntry] = []
        # What each entry depends on, by UUID: `deps` is a list of names where they are unique in
        # the manifest, and a table of name = UUID where two packages share a name.
        wants: list[set[str]] = []
        uuids_of: dict[str, set[str]] = {}
        for name, records in packages.items():
            for record in records if isinstance(records, list) else ():
                if isinstance(record, dict) and isinstance(record.get("uuid"), str):
                    uuids_of.setdefault(name, set()).add(record["uuid"].lower())
        for name, records in sorted(packages.items()):
            if not isinstance(records, list):
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a package that is not an array of tables",
                )
            for record in records:
                if not isinstance(record, dict):
                    continue
                uuid = record.get("uuid")
                if not isinstance(uuid, str) or not UUID.match(uuid):
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error="a package without a UUID",
                    )
                tree = BaseEcosystem._s(record.get("git-tree-sha1"))
                url = BaseEcosystem._s(record.get("repo-url"))
                path = BaseEcosystem._s(record.get("path"))
                rev = BaseEcosystem._s(record.get("repo-rev"))
                version = BaseEcosystem._s(record.get("version")) or ""
                resolved = None
                if url:
                    # Pkg checks out the tree with this hash, whatever the branch or tag now names:
                    # the content is pinned by the tree, not by `repo-rev`.
                    resolved = (
                        f"git+{url}#{tree}" if tree else f"git+{url}" + (f"#{rev}" if rev else "")
                    )
                elif path:
                    resolved = f"path:{path}"
                deps = record.get("deps")
                names = list(deps) if isinstance(deps, (list, dict)) else []
                if isinstance(deps, dict):
                    wants.append({str(v).lower() for v in deps.values()})
                else:
                    wants.append({u for n in names for u in uuids_of.get(str(n), set())})
                stdlib = not tree and not url and not path
                entries.append(
                    LockEntry(
                        name=name,
                        version=version,
                        integrity=f"git-tree-sha1:{tree}" if tree else None,
                        resolved_from=resolved,
                        dependencies=tuple(str(n) for n in names),
                        # A standard library ships inside Julia: no tree hash, no download. A format
                        # 1 manifest gives it no version either: the Julia installation meets it.
                        bundled=stdlib,
                        scope=Scope.PLATFORM if stdlib and not version else Scope.RUNTIME,
                        local=bool(path),
                        platform=JuliaToml.identity(uuid),
                    )
                )
        entries = JuliaManifest._directness(entries, wants)
        julia = data.get("julia_version")
        if isinstance(julia, str):
            entries.append(
                LockEntry(name="julia", version=julia, scope=Scope.PLATFORM, direct=True)
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def _directness(entries: list[LockEntry], wants: list[set[str]]) -> list[LockEntry]:
        """A manifest marks nothing direct: what no other package depends on is the project's.
        A workspace manifest lists the root package itself (`path = "."`); what it depends on is
        what the project depends on, not something another package pulled in."""
        required = {
            u
            for e, w in zip(entries, wants, strict=True)
            if e.resolved_from not in ("path:.", "path:./")
            for u in w
        }
        return [
            dataclasses.replace(
                e,
                direct=e.direct
                or not any(
                    c.removeprefix("uuid ") in required for c in e.platform if c.startswith("uuid ")
                ),
            )
            for e in entries
        ]


class Artifacts:
    """Artifacts.toml: platform-specific binaries, each pinned by content hash."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = tomllib.loads(content.text)
        except tomllib.TOMLDecodeError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid TOML: {exc}"
            )
        entries: list[LockEntry] = []
        for name, value in sorted(data.items()):
            variants = (
                value if isinstance(value, list) else [value] if isinstance(value, dict) else []
            )
            if not variants:
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="an artifact that is not a table",
                )
            for variant in variants:
                if not isinstance(variant, dict):
                    continue
                tree = BaseEcosystem._s(variant.get("git-tree-sha1"))
                if not tree:
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error="an artifact without its git-tree-sha1",
                    )
                downloads = variant.get("download")
                first = (
                    downloads[0]
                    if isinstance(downloads, list) and downloads and isinstance(downloads[0], dict)
                    else {}
                )
                digest = BaseEcosystem._s(first.get("sha256"))
                platform = tuple(
                    f"{key} {variant[key]}"
                    for key in (
                        "os",
                        "arch",
                        "libc",
                        "call_abi",
                        "cxxstring_abi",
                        "libgfortran_version",
                    )
                    if isinstance(variant.get(key), str)
                )
                entries.append(
                    LockEntry(
                        name=f"artifact:{name}",
                        # The content's tree hash names the artifact; there is no other version.
                        version=tree[:12],
                        integrity=f"sha256:{digest}" if digest else f"git-tree-sha1:{tree}",
                        # Pkg fetches an artifact from the package server by its tree hash, and
                        # falls back to the listed URLs only when the server has not got it.
                        resolved_from=f"https://pkg.julialang.org/artifact/{tree}",
                        platform=platform,
                        direct=True,
                    )
                )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class JuliaEcosystem(BaseEcosystem):
    """Julia packages through Pkg."""

    id = "julia"
    purl_type = "julia"
    manifest_globs: tuple[str, ...] = ("**/Project.toml", "**/JuliaProject.toml")
    lockfile_globs: tuple[str, ...] = (
        "**/Manifest.toml",
        "**/JuliaManifest.toml",
        "**/Manifest-v*.toml",
        "**/Artifacts.toml",
    )
    registry_hosts: frozenset[str] = frozenset({"pkg.julialang.org", "github.com/juliaregistries"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """`?uuid=...`: the package's identity, as the purl-spec julia type requires."""
        for condition in platform:
            kind, _, value = condition.partition(" ")
            if kind == "uuid" and UUID.match(value):
                return f"?uuid={value}"
        return ""

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        manifest = Project.parse(content, self.id)
        root = Project.workspace_root(content.path, files)
        if root is not None and manifest.parse_error is None:
            return dataclasses.replace(manifest, locked_by=root)
        return manifest

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "Artifacts.toml":
            return Artifacts.parse(content, self.id)
        return JuliaManifest.parse(content, self.id)


__all__ = ["Artifacts", "JuliaEcosystem", "JuliaManifest", "Project"]
