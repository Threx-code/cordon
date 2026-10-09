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


#: The standard libraries of Julia 1.11, by UUID (`Pkg.Types.stdlibs()`): they ship inside Julia,
#: so a project that depends on one downloads nothing for it.
STDLIBS: frozenset[str] = frozenset(
    {
        "0dad84c5-d112-42e6-8d28-ef12dabb789f",  # ArgTools
        "56f22d72-fd6d-98f1-02f0-08ddc0907c33",  # Artifacts
        "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f",  # Base64
        "8bf52ea8-c179-5cab-976a-9e18b702a9bc",  # CRC32c
        "e66e0078-7015-5450-92f7-15fbd957f2ae",  # CompilerSupportLibraries_jll
        "ade2ca70-3891-5945-98fb-dc099432e06a",  # Dates
        "8ba89e20-285c-5b6f-9357-94700520ee1b",  # Distributed
        "f43a241f-c20a-4ad4-852c-f6b1247861c6",  # Downloads
        "7b1f6079-737a-58dc-b8bc-7a2ca5c1b5ee",  # FileWatching
        "9fa8497b-333b-5362-9e8d-4d0656e87820",  # Future
        "781609d7-10c4-51f6-84f2-b8444358ff6d",  # GMP_jll
        "b77e0a4c-d291-57a0-90e8-8db25a27a240",  # InteractiveUtils
        "d55e3150-da41-5e91-b323-ecfd1eec6109",  # LLD_jll
        "47c5dbc3-30ba-59ef-96a6-123e260183d9",  # LLVMLibUnwind_jll
        "4af54fe1-eca0-43a8-85a7-787d91b784e3",  # LazyArtifacts
        "b27032c2-a3e7-50c8-80cd-2d36dbcbfd21",  # LibCURL
        "deac9b47-8bc7-5906-a0fe-35ac56dc84c0",  # LibCURL_jll
        "76f85450-5226-5b5a-8eaa-529ad045b433",  # LibGit2
        "e37daf67-58a4-590a-8e99-b0245dd2ffc5",  # LibGit2_jll
        "29816b5a-b9ab-546f-933c-edad1886dfa8",  # LibSSH2_jll
        "183b4373-6708-53ba-ad28-60e28bb38547",  # LibUV_jll
        "745a5e78-f969-53e9-954f-d19f2f74f4e3",  # LibUnwind_jll
        "8f399da3-3557-5675-b5ff-fb832c97cbdb",  # Libdl
        "37e2e46d-f89d-539d-b4ee-838fcccc9c8e",  # LinearAlgebra
        "56ddb016-857b-54e1-b83d-db4d58db5568",  # Logging
        "3a97d323-0669-5f0c-9066-3539efd106a3",  # MPFR_jll
        "d6f4376e-aef5-505a-96c1-9c027394607a",  # Markdown
        "c8ffd9c3-330d-5841-b78e-0817d7145fa1",  # MbedTLS_jll
        "a63ad114-7e13-5084-954f-fe012c677804",  # Mmap
        "14a3606d-f60d-562e-9121-12d972cd8159",  # MozillaCACerts_jll
        "ca575930-c2e3-43a9-ace4-1e988b2c1908",  # NetworkOptions
        "4536629a-c528-5b80-bd46-f80d51c5b363",  # OpenBLAS_jll
        "05823500-19ac-5b8b-9628-191a04bc5112",  # OpenLibm_jll
        "efcefdf7-47ab-520b-bdef-62a2eaa19f15",  # PCRE2_jll
        "44cfe95a-1eb2-52ea-b672-e2afdf69b78f",  # Pkg
        "de0858da-6303-5e67-8744-51eddeeeb8d7",  # Printf
        "9abbd945-dff8-562f-b5e8-e1ebf5ef1b79",  # Profile
        "3fa0cd96-eef1-5676-8a61-b3b8758bbffb",  # REPL
        "9a3f8284-a2c9-5f02-9a11-845980a1fd5c",  # Random
        "ea8e919c-243c-51af-8825-aaa63cd721ce",  # SHA
        "9e88b42a-f829-5b0c-bbe9-9e923198166b",  # Serialization
        "1a1011a3-84de-559e-8e89-a11a2f7dc383",  # SharedArrays
        "6462fe0b-24de-5631-8697-dd941f90decc",  # Sockets
        "2f01184e-e22b-5df5-ae63-d93ebab69eaf",  # SparseArrays
        "f489334b-da3d-4c2e-b8f0-e476e12c162b",  # StyledStrings
        "4607b0f0-06f3-5cda-b6b1-a6196a1729e9",  # SuiteSparse
        "bea87d4a-7f5b-5778-9afe-8cc45184846c",  # SuiteSparse_jll
        "fa267f1f-6049-4f14-aa54-33bafae1ed76",  # TOML
        "a4e569a6-e804-4fa4-b0f3-eef7a1d5b13e",  # Tar
        "8dfed614-e22c-5e08-85e1-65c5234f0b40",  # Test
        "cf7118a7-6976-5b1a-9a39-7adc72f591a4",  # UUIDs
        "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5",  # Unicode
        "83775a58-1f1d-513f-b197-d71354ab007a",  # Zlib_jll
        "05ff407c-b0c1-5878-9df8-858cc2e60c36",  # dSFMT_jll
        "8f36deef-c2a5-5394-99ed-8e07531fb29a",  # libLLVM_jll
        "8e850b90-86db-534c-a0d3-1478176c7d93",  # libblastrampoline_jll
        "8e850ede-7688-5339-a07c-302acd2aaf8d",  # nghttp2_jll
        "3f19e933-33d8-53b3-aaab-bd5110c3b7a0",  # p7zip_jll
    }
)
STDLIB_NOTE = "a Julia standard library: it ships inside Julia, so nothing is downloaded for it"
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

        def stdlib(name: str, uuid: Any) -> bool:
            return str(uuid).lower() in STDLIBS and name not in sources

        for name, uuid in deps.items():
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.PLATFORM if stdlib(name, uuid) else Scope.RUNTIME,
                    field_name="deps",
                    platform=JuliaToml.identity(uuid),
                    note=STDLIB_NOTE if stdlib(name, uuid) else None,
                )
            )
        for name, uuid in weak.items():
            unlocks = ", ".join(sorted(enables.get(name, []))) or "no extension"
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.PLATFORM if stdlib(name, uuid) else Scope.OPTIONAL,
                    field_name="weakdeps",
                    platform=JuliaToml.identity(uuid),
                    note=f"a weak dependency on a Julia standard library, which loads {unlocks}"
                    if stdlib(name, uuid)
                    else f"a weak dependency: installed only by a user who adds it, which loads {unlocks}",
                )
            )
        for name, uuid in extras.items():
            if name in deps or name in weak:
                continue
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec(name)[0],
                    scope=Scope.PLATFORM
                    if stdlib(name, uuid)
                    else Scope.TEST
                    if name in test_only
                    else Scope.DEV,
                    field_name="extras",
                    platform=JuliaToml.identity(uuid),
                    note=STDLIB_NOTE
                    if stdlib(name, uuid)
                    else "a test-only dependency ([extras] and [targets]): resolved when the tests run, not into the manifest",
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
