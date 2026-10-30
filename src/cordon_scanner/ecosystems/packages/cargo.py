"""Cargo: Cargo.toml and Cargo.lock, the features a manifest declares, and the registries .cargo/config names."""

from __future__ import annotations

import tomllib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

# Each `*Ecosystem` imported below from its own module (GitHub Actions, Bazel, CocoaPods, Composer,
# Conan, Conda, CRAN, Gradle, Hex, NuGet, Pub, RubyGems, Swift) is re-exported where it always lived.
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class CargoEcosystem(BaseEcosystem):
    id = "cargo"
    purl_type = "cargo"
    manifest_globs: tuple[str, ...] = ("**/Cargo.toml", "**/.cargo/config.toml", "**/.cargo/config")
    lockfile_globs: tuple[str, ...] = ("**/Cargo.lock",)
    registry_hosts: frozenset[str] = frozenset(
        {
            "crates.io",
            "static.crates.io",
            # What a `Cargo.lock` actually records. Cargo names its default
            # registry by the index repository rather than by the download
            # host, so every crate in every lockfile read as "resolved from
            # outside the registry" -- forty-two findings in ripgrep alone,
            # for a completely ordinary dependency set.
            "index.crates.io",
        }
    )

    REGISTRY_INDEXES: frozenset[str] = frozenset(
        {
            "github.com/rust-lang/crates.io-index",
            "index.crates.io",
        }
    )
    """How a `Cargo.lock` names the default registry.

    Cargo records `registry+https://github.com/rust-lang/crates.io-index`, which
    identifies the registry by its *index repository* rather than by a download
    host -- so a host-only comparison sees `github.com` and concludes every
    crate came from outside the registry. That was forty-two findings in
    ripgrep alone, for a completely ordinary dependency set."""

    def is_registry_host(self, url: str | None) -> bool:
        """Whether a Cargo resolution points at the default registry.

        The `registry+` prefix is stripped first: it is Cargo's way of saying
        "this came from a registry", and the base implementation reads any
        `<scheme>+` as a version-control reference, which for Cargo is exactly
        backwards.
        """
        if url and url.lower().startswith("registry+"):
            remainder = url[len("registry+") :].lower().rstrip("/")
            return any(index in remainder for index in self.REGISTRY_INDEXES)
        return super().is_registry_host(url)

    def normalize_name(self, name: str) -> str:
        # crates.io treats hyphen and underscore as equivalent when checking for
        # a conflicting name, so the two forms must fold together or every
        # crate has a free typosquat.
        return name.strip().lower().replace("_", "-")

    SECTIONS: ClassVar[tuple[tuple[str, Scope], ...]] = (
        ("dependencies", Scope.RUNTIME),
        ("dev-dependencies", Scope.DEV),
        ("build-dependencies", Scope.BUILD),
    )

    @staticmethod
    def _declaration(
        key: str, spec: object, scope: Scope, field_name: str, platform: tuple[str, ...]
    ) -> DeclaredDependency:
        """One `[dependencies]` entry: a version string or a table.

        ```
          serde = { version = "1", features = ["derive"] }        features -> extras
          rand_core_alias = { package = "rand_core", ... }         a rename: the crate is rand_core
          log = { version = "0.4", optional = true }               only with a feature that enables it
          itoa = { git = "https://...", tag = "1.0.11" }           a git source at a tag, rev or branch
          util = { path = "../util" }                              the workspace's own code
          anyhow = { workspace = true }                            the constraint is the workspace's
        ```
        """
        if not isinstance(spec, dict):
            return DeclaredDependency(
                name=key, spec=str(spec), scope=scope, field_name=field_name, platform=platform
            )
        name = str(spec.get("package") or key)
        text = BaseEcosystem._table_spec(spec)
        if isinstance(spec.get("git"), str):
            ref = next(
                (
                    f"{k}={spec[k]}"
                    for k in ("rev", "tag", "branch")
                    if isinstance(spec.get(k), str)
                ),
                None,
            )
            text = f"git+{spec['git']}" + (f"?{ref}" if ref else "")
        features = spec.get("features")
        registry = spec.get("registry") or spec.get("registry-index")
        return DeclaredDependency(
            name=name,
            spec=text,
            scope=Scope.OPTIONAL
            if spec.get("optional") is True and scope is Scope.RUNTIME
            else scope,
            field_name=field_name,
            platform=platform,
            alias=key if name != key else None,
            extras=tuple(str(f) for f in features) if isinstance(features, list) else (),
            source=f"registry:{registry}" if isinstance(registry, str) else None,
        )

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename in ("config.toml", "config") and "/.cargo/" in f"/{content.path}":
            return CargoConfig.parse(content, self.id)
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, self.id, f"invalid TOML: {exc}")

        declared: list[DeclaredDependency] = []
        for section, scope in self.SECTIONS:
            for name, spec in (data.get(section) or {}).items():
                declared.append(self._declaration(str(name), spec, scope, section, ()))
        # `[target.'cfg(windows)'.dependencies]`: only on the platforms the cfg selects.
        targets = data.get("target")
        if isinstance(targets, dict):
            for condition, tables in targets.items():
                if not isinstance(tables, dict):
                    continue
                for section, scope in self.SECTIONS:
                    for name, spec in (tables.get(section) or {}).items():
                        declared.append(
                            self._declaration(
                                str(name),
                                spec,
                                scope,
                                f"target.{condition}.{section}",
                                (str(condition),),
                            )
                        )
        raw_package, raw_workspace = data.get("package"), data.get("workspace")
        package_table: dict[str, Any] = raw_package if isinstance(raw_package, dict) else {}
        workspace: dict[str, Any] = raw_workspace if isinstance(raw_workspace, dict) else {}
        raw_shared_package = workspace.get("package")
        shared_package: dict[str, Any] = (
            raw_shared_package if isinstance(raw_shared_package, dict) else {}
        )
        rust = package_table.get("rust-version")
        if isinstance(rust, dict) and rust.get("workspace") is True:
            rust = shared_package.get("rust-version")
        if rust is None:
            rust = shared_package.get("rust-version")
        if isinstance(rust, str) and rust:
            declared.append(
                DeclaredDependency(
                    name="rust", spec=f">={rust}", scope=Scope.PLATFORM, field_name="rust-version"
                )
            )
        shared = {
            str(name): (spec if isinstance(spec, str) else BaseEcosystem._table_spec(spec))
            for name, spec in (workspace.get("dependencies") or {}).items()
        }
        declared = CargoFeatures.annotate(declared, data.get("features"))

        # build.rs is arbitrary Rust compiled and run during every build, with
        # full access to the build machine. It is Cargo's equivalent of an
        # install script and is registered whether declared explicitly or found
        # by convention.
        hooks: list[Hook] = []
        package = data.get("package") or {}
        build = package.get("build")
        if build:
            hooks.append(
                Hook(
                    kind="build",
                    path=content.path,
                    name="build",
                    command=str(build),
                    ecosystem=self.id,
                )
            )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=BaseEcosystem._s(package.get("name")),
            version=BaseEcosystem._s(package.get("version")),
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            shared_specs=shared,
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )
        packages = [p for p in data.get("package") or [] if isinstance(p, dict) and p.get("name")]
        if data.get("package") and not packages:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error="no [[package]] could be read"
            )
        # Version 1 lockfiles keep checksums in a `[metadata]` table keyed by "checksum name version
        # (source)"; versions 2 to 4 keep them on each package.
        raw_legacy = data.get("metadata")
        legacy: dict[str, Any] = raw_legacy if isinstance(raw_legacy, dict) else {}
        by_name: dict[str, list[str]] = {}
        for package in packages:
            by_name.setdefault(str(package["name"]), []).append(str(package.get("version", "")))
        entries = []
        for package in packages:
            name, version = str(package["name"]), str(package.get("version", ""))
            source = BaseEcosystem._s(package.get("source"))
            checksum = BaseEcosystem._s(package.get("checksum"))
            if checksum is None and source:
                checksum = BaseEcosystem._s(legacy.get(f"checksum {name} {version} ({source})"))
            edges: list[str] = []
            for raw in package.get("dependencies") or []:
                # `serde`, or `serde 1.0.210` when two versions are locked, or with `(source)`.
                parts = str(raw).split()
                if len(parts) >= 2:
                    edges.append(f"{parts[0]}@{parts[1]}")
                elif parts:
                    versions = by_name.get(parts[0], [])
                    edges.append(f"{parts[0]}@{versions[0]}" if len(versions) == 1 else parts[0])
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=checksum,
                    resolved_from=source,
                    # No `source` means a workspace member or a path dependency: the
                    # crate is in this repository. Cargo writes no checksum for those
                    # because there is nothing to check against.
                    local=not source,
                    dependencies=tuple(sorted(edges)),
                )
            )
        # The workspace's own crates: no source. They are the members whose manifests the graph
        # resolves, so their dependencies are what the project declares directly.
        members = {e.name for e in entries if e.local}
        direct = {
            edge.partition("@")[0]
            for e in entries
            if e.local
            for edge in e.dependencies
            if edge.partition("@")[0] not in members
        }
        entries = [
            LockEntry(
                name=e.name,
                version=e.version,
                integrity=e.integrity,
                resolved_from=e.resolved_from,
                local=e.local,
                dependencies=e.dependencies,
                direct=e.name in direct or e.local,
            )
            for e in entries
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    # -- the projects mcp writes for a package check (EcosystemProjects) ------------

    def pinned_project(self, pins: Sequence[tuple[str, str]]) -> dict[str, str] | None:
        """A project pinning these releases, as its own lockfile: `{path: content}`."""
        return {
            "Cargo.lock": "version = 3\n"
            + "".join(
                f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                for name, version in pins
            )
        }

    def loose_project(self, names: Sequence[str]) -> dict[str, str] | None:
        """A project naming these packages with no version: `{path: content}`."""
        deps = "".join(f'"{name}" = "*"\n' for name in names)
        return {
            "Cargo.toml": f'[package]\nname = "cordon-check"\nversion = "0.0.0"\n\n[dependencies]\n{deps}'
        }


class CargoFeatures:
    """Which features enable each optional dependency, and whether the defaults do.

    Declaring `log = { optional = true }` and enabling it are different facts: the lockfile
    resolves every optional dependency, and only an enabled feature compiles one in. Each optional
    dependency's condition is recorded as the features that enable it, and whether `default`
    reaches any of them -- the spec's "feature activation separately from merely declaring".

    ```
      [features]
      default = ["std"]            std -> serde/std          (a feature of another crate)
      logging = ["dep:log"]        dep:log                   (enables the optional dependency)
      tracing = ["tracing-core"]   tracing-core              (implicit feature of an optional dep)
    ```
    """

    @staticmethod
    def annotate(declared: list[DeclaredDependency], features: object) -> list[DeclaredDependency]:
        table = features if isinstance(features, dict) else {}
        enables: dict[str, set[str]] = {}
        for feature, members in table.items():
            for member in members if isinstance(members, list) else ():
                target = str(member).removeprefix("dep:").split("/", 1)[0].rstrip("?")
                enables.setdefault(target, set()).add(str(feature))
        reached: set[str] = set()
        pending = ["default"]
        while pending:
            feature = pending.pop()
            if feature in reached:
                continue
            reached.add(feature)
            for member in table.get(feature, ()) if isinstance(table.get(feature), list) else ():
                pending.append(str(member).removeprefix("dep:").split("/", 1)[0].rstrip("?"))
        out: list[DeclaredDependency] = []
        for entry in declared:
            if entry.scope is not Scope.OPTIONAL:
                out.append(entry)
                continue
            key = entry.alias or entry.name
            gates = sorted(enables.get(key, set()) | ({key} if key not in enables else set()))
            on_by_default = key in reached or any(g in reached for g in gates)
            condition = (
                f"feature {', '.join(gates)} (enabled by default)"
                if on_by_default
                else f"feature {', '.join(gates)} (not enabled by default)"
            )
            out.append(
                DeclaredDependency(
                    name=entry.name,
                    spec=entry.spec,
                    scope=entry.scope,
                    field_name=entry.field_name,
                    platform=(*entry.platform, condition),
                    alias=entry.alias,
                    extras=entry.extras,
                    source=entry.source,
                )
            )
        return out


class CargoConfig:
    """`.cargo/config.toml`: the registries Cargo resolves from, and whether crates.io is replaced.

    ```
      [registries.internal]            index = "sparse+https://cargo.example.internal/index/"
      [source.crates-io]               replace-with = "vendored-sources"
      [source.vendored-sources]        directory = "vendor"
    ```

    A replaced crates.io is served from the replacement while `Cargo.lock` still names
    crates.io: the lockfile's checksums are still checked, against whatever the replacement
    serves. Recorded as the sources the project resolves from.
    """

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid TOML: {exc}")
        sources: list[str] = []
        registries = data.get("registries")
        if isinstance(registries, dict):
            for name, table in sorted(registries.items()):
                if isinstance(table, dict) and isinstance(table.get("index"), str):
                    sources.append(f"registry {name}: {table['index']}")
        replacements = data.get("source")
        if isinstance(replacements, dict):
            for name, table in sorted(replacements.items()):
                if not isinstance(table, dict):
                    continue
                if isinstance(table.get("replace-with"), str):
                    sources.append(f"source {name} replaced with {table['replace-with']}")
                for key in ("registry", "directory", "local-registry", "git"):
                    if isinstance(table.get(key), str):
                        sources.append(f"source {name}: {key} {table[key]}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


__all__ = ["CargoConfig", "CargoEcosystem", "CargoFeatures"]
