"""The remaining ecosystems: Maven, Gradle, Cargo, Go, NuGet, Composer,
RubyGems, CocoaPods and pub.

Each is deliberately small. That is the architectural claim being tested:
supporting an ecosystem should cost a parser and a name-normalisation rule, not
a change to the engine, the rule packs or the detectors.

Every one of them implements the same two things that actually matter for
supply-chain risk: which paths execute during a build, and whether a dependency
resolves from somewhere other than the ecosystem's own registry.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.core.safexml import Element, SafeXml, SafeXmlError

# Each `*Ecosystem` imported below from its own module (GitHub Actions, Bazel, CocoaPods, Composer,
# Conan, Conda, CRAN, Gradle, Hex, NuGet, Pub, RubyGems, Swift) is re-exported where it always lived.
from cordon_scanner.ecosystems.actions import GitHubActionsEcosystem
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.bazel import BazelEcosystem
from cordon_scanner.ecosystems.cocoapods import CocoaPodsEcosystem
from cordon_scanner.ecosystems.composer import ComposerEcosystem
from cordon_scanner.ecosystems.conan import ConanEcosystem
from cordon_scanner.ecosystems.conda import CondaEcosystem
from cordon_scanner.ecosystems.cran import CranEcosystem
from cordon_scanner.ecosystems.gradle import GradleEcosystem
from cordon_scanner.ecosystems.hex import HexEcosystem
from cordon_scanner.ecosystems.nuget import NuGetEcosystem
from cordon_scanner.ecosystems.pub import PubEcosystem
from cordon_scanner.ecosystems.rubygems import RubyGemsEcosystem
from cordon_scanner.ecosystems.swift import SwiftEcosystem

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------


class GoModFile:
    """One `go.mod`, read once for both of the questions asked of it.

    From Go 1.17 a module's `go.mod` lists every module its build needs, each at the version
    minimal version selection chose, with `// indirect` on the ones no package of the module
    imports directly. That is the resolution: `go.sum` is not -- it keeps hashes for versions the
    build no longer selects, and for module files only -- so `go.mod` is read as the lockfile and
    `go.sum` completes it with integrity (see `LockGraph.companion`).
    """

    _REQUIRE: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*([^\s()]+)\s+(v[^\s/]+)(\s*//\s*indirect)?"
    )
    _REPLACE: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:replace\s+)?(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?\s*$"
    )
    """`replace old [vX] => new [vY]`, on one line or inside a `replace ( ... )` block."""
    _EXCLUDE: ClassVar[re.Pattern[str]] = re.compile(r"^\s*(?:exclude\s+)?(\S+)\s+(v\S+)\s*$")
    _GO_DIRECTIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(go|toolchain)\s+(?:go)?(\d{1,4}(?:\.\d{1,6}){1,2})\s*$"
    )
    _TOOL: ClassVar[re.Pattern[str]] = re.compile(r"^\s*(?:tool\s+)?([^\s()]+)\s*$")

    #: Every directive `go.mod` and `go.work` allow. The go command refuses anything else, and so
    #: does this reader: a line it skipped silently was a file it reported as read.
    BLOCKS: ClassVar[frozenset[str]] = frozenset(
        {"require", "replace", "exclude", "retract", "tool", "godebug", "ignore", "use"}
    )

    def __init__(self, text: str) -> None:
        self.module: str | None = None
        self.requires: list[tuple[str, str, bool]] = []
        self.replaces: dict[str, tuple[str, str | None]] = {}
        self.excludes: set[tuple[str, str]] = set()
        self.tools: list[str] = []
        self.language: str | None = None
        self.toolchain: str | None = None
        self.errors: list[str] = []
        block: str | None = None
        block_line = 0
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            stripped = line.split("//", 1)[0].strip() if "indirect" not in line else line.strip()
            if not stripped:
                continue
            plain = stripped.split("//", 1)[0].strip()
            if block is None and plain.startswith("module "):
                self.module = plain.split(None, 1)[1].strip().strip('"')
                continue
            directive = self._GO_DIRECTIVE.match(plain)
            if directive and block is None:
                if directive.group(1) == "toolchain":
                    self.toolchain = directive.group(2)
                else:
                    self.language = directive.group(2)
                continue
            if block is None and re.match(r"^toolchain\s+(?:default|go\S+)$", plain):
                continue
            opened = re.match(r"^(\w+)\s*\(\s*$", plain)
            if opened and block is None:
                # Errors name the line and never repeat its text: a go.mod is attacker-shaped
                # input, and whatever sits on a malformed line (a token pasted by mistake) would
                # otherwise travel into every report format.
                if opened.group(1) not in self.BLOCKS:
                    self.errors.append(f"line {number}: a block opened by an unknown directive")
                block, block_line = opened.group(1), number
                continue
            if block is not None and plain == ")":
                block = None
                continue
            kind = block
            body = stripped
            if block is None:
                word = plain.split(None, 1)[0]
                if word not in self.BLOCKS or len(plain.split(None, 1)) < 2:
                    self.errors.append(f"line {number}: not a go.mod directive")
                    continue
                kind, body = word, stripped[len(word) :].strip()
            matched = True
            if kind == "require":
                found = self._REQUIRE.match(body)
                matched = found is not None
                if found:
                    self.requires.append((found.group(1), found.group(2), bool(found.group(3))))
            elif kind == "replace":
                found = self._REPLACE.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.replaces[found.group(1)] = (found.group(3), found.group(4))
            elif kind == "exclude":
                found = self._EXCLUDE.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.excludes.add((found.group(1), found.group(2)))
            elif kind == "tool":
                found = self._TOOL.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.tools.append(found.group(1))
            elif kind == "retract":
                matched = bool(
                    re.match(
                        r"^(?:v\S+|\[\s*v\S+\s*,\s*v\S+\s*\])$", body.split("//", 1)[0].strip()
                    )
                )
            elif kind == "godebug":
                matched = bool(re.match(r"^[\w.-]+=\S+$", body.split("//", 1)[0].strip()))
            elif kind in ("use", "ignore"):
                matched = bool(body.split("//", 1)[0].strip())
            if not matched:
                self.errors.append(f"line {number}: malformed {kind} entry")
        if block is not None:
            self.errors.append(f"line {block_line}: {block} block is never closed")

    @property
    def stdlib(self) -> str | None:
        """The standard library's version: the toolchain directive's, or failing that the `go`
        directive's -- the reading govulncheck and OSV-Scanner apply."""
        version = self.toolchain or self.language
        if not version:
            return None
        parts = version.split(".")
        return "v" + ".".join(parts + ["0"] * (3 - len(parts)))

    @staticmethod
    def lists_direct_only(language: str | None) -> bool:
        """Whether a `go.mod` at this `go` version leaves its indirect modules out: before 1.17
        (and with no `go` line, which the go command reads as 1.16) only `go.sum` names them."""
        if not language:
            return True
        parts = language.split(".")
        try:
            return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0) < (1, 17)
        except ValueError:
            return False

    def untidied(self) -> bool:
        """A 1.17-or-later `go.mod` that requires modules but marks none `// indirect` was not
        tidied under 1.17's rules (its `go` line was raised by hand, or `go mod tidy` never ran),
        so it too names only what it imports. `go.sum` then completes it: a module whose
        requirements really have no dependencies of their own adds nothing from it."""
        return bool(self.requires) and not any(indirect for _, _, indirect in self.requires)

    def tool_modules(self) -> set[str]:
        """Modules that provide a `tool` directive's package (the longest required prefix)."""
        provided: set[str] = set()
        for tool in self.tools:
            owners = [
                name for name, _, _ in self.requires if tool == name or tool.startswith(name + "/")
            ]
            if owners:
                provided.add(max(owners, key=len))
        return provided


class GoEcosystem(BaseEcosystem):
    id = "gomod"
    purl_type = "golang"
    manifest_globs: tuple[str, ...] = ("**/go.mod", "**/go.work")
    lockfile_globs: tuple[str, ...] = (
        "**/go.mod",
        "**/go.sum",
        "**/go.work.sum",
        "**/vendor/modules.txt",
    )
    registry_hosts: frozenset[str] = frozenset({"proxy.golang.org", "sum.golang.org"})

    def normalize_name(self, name: str) -> str:
        """Go module paths are case-sensitive but case-encoded in the proxy.

        Lowercased for comparison only. Two paths differing solely in case are a
        classic confusion vector, so they must compare equal for typosquat
        purposes even though they are distinct modules.
        """
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        """What a `go.mod` declares: the modules it requires directly (not `// indirect`, which
        the go command records for the build and nobody wrote), replacement targets, tools, the
        Go version, and the standard library the toolchain compiles in. A `go.work` declares the
        modules of a workspace, which are read as projects of their own."""
        if content.basename == "go.work":
            return GoWork.parse(content, self.id)
        mod = GoModFile(content.text)
        if mod.errors:
            return BaseEcosystem._err(content, self.id, "; ".join(mod.errors[:3]))
        declared: list[DeclaredDependency] = []
        tools = mod.tool_modules()
        for name, version, indirect in mod.requires:
            if indirect and name not in tools:
                continue
            if (name, version) in mod.excludes:
                continue
            target, target_version = mod.replaces.get(name, (None, None))
            if target is not None and target.startswith((".", "/")):
                declared.append(
                    DeclaredDependency(
                        name=name, spec=target, scope=Scope.RUNTIME, field_name="replace"
                    )
                )
                continue
            if target is not None and target_version:
                declared.append(
                    DeclaredDependency(
                        name=target,
                        spec=target_version,
                        scope=Scope.RUNTIME,
                        field_name="replace",
                        alias=name,
                    )
                )
                continue
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=version,
                    scope=Scope.TOOL if name in tools else Scope.RUNTIME,
                    field_name="tool" if name in tools else "require",
                )
            )
        if mod.stdlib:
            # The standard library is compiled into every binary at the toolchain's version; Go's
            # advisories file it under the module `stdlib`, and without it a `net/http` or
            # `crypto/tls` advisory matched no module in the graph.
            declared.append(
                DeclaredDependency(
                    name="stdlib", spec=mod.stdlib, scope=Scope.RUNTIME, field_name="toolchain"
                )
            )
        if mod.language:
            declared.append(
                DeclaredDependency(
                    name="go", spec=f">={mod.language}", scope=Scope.PLATFORM, field_name="go"
                )
            )
        return Manifest(
            path=content.path, ecosystem=self.id, name=mod.module, dependencies=tuple(declared)
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name in ("go.sum", "go.work.sum"):
            return self._parse_sum(content)
        if name == "modules.txt":
            return self._parse_vendor(content)
        return self._parse_build_list(content)

    def _parse_build_list(self, content: FileContent) -> LockGraph:
        """`go.mod`'s requirements as the resolution: every module at the selected version, direct
        unless `// indirect`, replacements applied, exclusions honoured."""
        mod = GoModFile(content.text)
        if mod.errors:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error="; ".join(mod.errors[:3])
            )
        tools = mod.tool_modules()
        entries: list[LockEntry] = []
        for name, version, indirect in mod.requires:
            if (name, version) in mod.excludes:
                continue
            target, target_version = mod.replaces.get(name, (None, None))
            if target is not None and target.startswith((".", "/")):
                # A local replacement: the module's code is the directory, read as source here.
                entries.append(
                    LockEntry(
                        name=name, version="", resolved_from=target, direct=not indirect, local=True
                    )
                )
                continue
            if target is not None and target_version:
                entries.append(
                    LockEntry(name=target, version=target_version, direct=not indirect, alias=name)
                )
                continue
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    direct=not indirect or name in tools,
                    scope=Scope.TOOL if name in tools else Scope.RUNTIME,
                )
            )
        if mod.stdlib:
            # BSD-3-Clause: the Go project's own licence for the standard library.
            entries.append(
                LockEntry(name="stdlib", version=mod.stdlib, direct=True, license="BSD-3-Clause")
            )
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            entries=tuple(entries),
            integrity_elsewhere=True,
            completed_by_companion=GoModFile.lists_direct_only(mod.language) or mod.untidied(),
        )

    def _parse_sum(self, content: FileContent) -> LockGraph:
        """`go.sum`: a hash of each module zip (`h1:`) and of each `go.mod` it read. Only zip
        hashes are integrity for a module's code; a `/go.mod` line hashes a file the build read
        to plan, not the code it compiled. A companion: it completes `go.mod`'s entries."""
        seen: dict[tuple[str, str], str] = {}
        for raw in content.text.splitlines():
            parts = raw.split()
            if len(parts) != 3 or parts[1].endswith("/go.mod"):
                continue
            seen.setdefault((parts[0], parts[1]), parts[2])
        entries = [LockEntry(name=n, version=v, integrity=d) for (n, v), d in sorted(seen.items())]
        return LockGraph(
            path=content.path, ecosystem=self.id, entries=tuple(entries), companion=True
        )

    def _parse_vendor(self, content: FileContent) -> LockGraph:
        """`vendor/modules.txt`: `# module version [=> replacement]` per vendored module, `##
        explicit` when go.mod requires it directly. A companion: the modules `go.mod` selects are
        built from the copies in `vendor/`."""
        entries: list[LockEntry] = []
        for raw in content.text.splitlines():
            if not raw.startswith("# "):
                continue
            parts = raw[2:].split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                entries.append(
                    LockEntry(
                        name=parts[0], version=parts[1], resolved_from=f"vendored:{content.path}"
                    )
                )
            elif len(parts) >= 3 and parts[1] == "=>":
                entries.append(
                    LockEntry(name=parts[0], version="", resolved_from=f"vendored:{content.path}")
                )
        return LockGraph(
            path=content.path, ecosystem=self.id, entries=tuple(entries), companion=True
        )


class GoWork:
    """`go.work`: the modules a workspace builds together (`use`), its Go version, and
    workspace-wide replacements. Each used module is a project with its own `go.mod`."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        mod = GoModFile(content.text)
        if mod.errors:
            return BaseEcosystem._err(content, ecosystem, "; ".join(mod.errors[:3]))
        uses: list[str] = []
        block = False
        for raw in content.text.splitlines():
            stripped = raw.split("//", 1)[0].strip()
            if stripped.startswith("use ("):
                block = True
                continue
            if block and stripped == ")":
                block = False
                continue
            if stripped.startswith("use "):
                uses.append(stripped[4:].strip())
            elif block and stripped:
                uses.append(stripped)
        declared: list[DeclaredDependency] = []
        if mod.language:
            declared.append(
                DeclaredDependency(
                    name="go", spec=f">={mod.language}", scope=Scope.PLATFORM, field_name="go"
                )
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            includes=tuple(("workspace", u) for u in uses),
        )


# ---------------------------------------------------------------------------
# Maven and Gradle
# ---------------------------------------------------------------------------


class MavenDependency:
    """One `<dependency>` as written, before interpolation and management."""

    __slots__ = (
        "artifact",
        "classifier",
        "exclusions",
        "group",
        "line",
        "optional",
        "scope",
        "type",
        "version",
    )

    def __init__(self, element: Element) -> None:
        self.group = element.value("groupId")
        self.artifact = element.value("artifactId")
        self.version = element.value("version")
        self.scope = element.value("scope").lower() or ""
        self.optional = element.value("optional").lower() == "true"
        self.classifier = element.value("classifier")
        self.type = element.value("type")
        self.exclusions = tuple(
            f"{e.value('groupId')}:{e.value('artifactId')}"
            for e in element.find_all("exclusions", "exclusion")
        )
        self.line = element.line


class MavenPom:
    """A POM's model, read structurally (`core/safexml.py`): what it declares, not yet resolved
    against its parent, its imports or the rest of the build."""

    def __init__(self, path: str, root: Element) -> None:
        self.path = path
        parent = root.find("parent")
        self.parent: tuple[str, str, str, str] | None = (
            (
                parent.value("groupId"),
                parent.value("artifactId"),
                parent.value("version"),
                parent.value("relativePath", default="../pom.xml"),
            )
            if parent is not None
            else None
        )
        self.group = root.value("groupId") or (self.parent[0] if self.parent else "")
        self.artifact = root.value("artifactId")
        self.version = root.value("version") or (self.parent[2] if self.parent else "")
        self.packaging = root.value("packaging") or "jar"
        self.properties = {
            c.local: c.text.strip() for c in (root.find("properties") or Element("p")).children
        }
        self.managed = [
            MavenDependency(d)
            for d in root.find_all("dependencyManagement", "dependencies", "dependency")
        ]
        self.dependencies = [
            MavenDependency(d) for d in root.find_all("dependencies", "dependency")
        ]
        self.modules = [m.text.strip() for m in root.find_all("modules", "module")]
        self.repositories = [
            (r.value("id"), r.value("url"))
            for r in root.find_all("repositories", "repository")
            + root.find_all("pluginRepositories", "pluginRepository")
        ]
        self.plugins = [
            (
                p.value("groupId") or "org.apache.maven.plugins",
                p.value("artifactId"),
                p.value("version"),
                p.line,
            )
            for p in root.find_all("build", "plugins", "plugin")
            + root.find_all("build", "pluginManagement", "plugins", "plugin")
        ]
        self.extensions = [
            (e.value("groupId"), e.value("artifactId"), e.value("version"), e.line)
            for e in root.find_all("build", "extensions", "extension")
        ]
        self.profiles: list[tuple[str, str, list[MavenDependency], dict[str, str]]] = []
        for profile in root.find_all("profiles", "profile"):
            activation = profile.find("activation")
            trigger = ""
            if activation is not None:
                parts = []
                for kind in ("activeByDefault", "jdk", "os", "property", "file"):
                    found = activation.find(kind)
                    if found is not None:
                        detail = found.text.strip() or " ".join(
                            f"{c.local}={c.text.strip()}" for c in found.children
                        )
                        parts.append(f"{kind} {detail}".strip())
                trigger = "; ".join(parts)
            self.profiles.append(
                (
                    profile.value("id"),
                    trigger,
                    [MavenDependency(d) for d in profile.find_all("dependencies", "dependency")],
                    {
                        c.local: c.text.strip()
                        for c in (profile.find("properties") or Element("p")).children
                    },
                )
            )


class MavenBuild:
    """Every POM in a scan, resolved together the way Maven resolves a reactor build.

    A module inherits its parent's properties, managed versions and dependencies; a parent is
    found by `relativePath` (default `../pom.xml`) or, failing that, by coordinates among the
    POMs scanned; an imported BOM (`<scope>import</scope>`) contributes its managed versions when
    it is in the tree. A parent or BOM that is not -- `spring-boot-starter-parent`, a company
    parent served from a repository -- cannot be read offline, and a version it would manage is
    reported as unresolved with that parent named, never guessed.
    """

    PLACEHOLDER: ClassVar[re.Pattern[str]] = re.compile(r"\$\{([A-Za-z0-9_.\-]{1,200})\}")
    MAX_PARENTS: ClassVar[int] = 16

    def __init__(self, poms: dict[str, MavenPom]) -> None:
        self.poms = poms
        self.by_coordinates = {f"{p.group}:{p.artifact}": p for p in poms.values() if p.artifact}

    def parent_of(self, pom: MavenPom) -> MavenPom | None:
        if pom.parent is None:
            return None
        group, artifact, _, relative = pom.parent
        if relative:
            base = pom.path.rpartition("/")[0]
            candidate = posixpath.normpath(posixpath.join(base, relative) if base else relative)
            if not candidate.endswith(".xml"):
                candidate = posixpath.join(candidate, "pom.xml")
            found = self.poms.get(candidate)
            if found is not None and found.artifact == artifact:
                return found
        return self.by_coordinates.get(f"{group}:{artifact}")

    def lineage(self, pom: MavenPom) -> tuple[list[MavenPom], str | None]:
        """The POM and its ancestors in the tree, nearest first, and the first ancestor that is
        not in the tree (`group:artifact:version`), if any."""
        chain = [pom]
        missing: str | None = None
        current = pom
        for _ in range(self.MAX_PARENTS):
            if current.parent is None:
                break
            parent = self.parent_of(current)
            if parent is None or parent in chain:
                missing = ":".join(current.parent[:3]) if parent is None else None
                break
            chain.append(parent)
            current = parent
        return chain, missing

    def properties(self, chain: list[MavenPom]) -> dict[str, str]:
        values: dict[str, str] = {}
        for pom in reversed(chain):
            values.update(pom.properties)
        own = chain[0]
        for prefix in ("project.", "pom.", ""):
            values.setdefault(f"{prefix}version", own.version)
            values.setdefault(f"{prefix}groupId", own.group)
            values.setdefault(f"{prefix}artifactId", own.artifact)
        if own.parent is not None:
            values.setdefault("project.parent.version", own.parent[2])
            values.setdefault("project.parent.groupId", own.parent[0])
        return values

    def interpolate(self, value: str, properties: dict[str, str]) -> str:
        for _ in range(8):
            expanded = self.PLACEHOLDER.sub(lambda m: properties.get(m.group(1), m.group(0)), value)
            if expanded == value:
                break
            value = expanded
        return value

    def managed(
        self, chain: list[MavenPom], properties: dict[str, str]
    ) -> tuple[dict[str, tuple[str, str]], list[str]]:
        """`group:artifact -> (version, scope)` from every `<dependencyManagement>` up the chain
        (nearest wins), BOM imports in the tree merged in, and the imports that are not."""
        managed: dict[str, tuple[str, str]] = {}
        unavailable: list[str] = []
        for pom in chain:
            for dependency in pom.managed:
                group = self.interpolate(dependency.group, properties)
                artifact = self.interpolate(dependency.artifact, properties)
                version = self.interpolate(dependency.version, properties)
                if dependency.scope == "import" and dependency.type == "pom":
                    bom = self.by_coordinates.get(f"{group}:{artifact}")
                    if bom is None:
                        unavailable.append(f"{group}:{artifact}:{version}")
                        continue
                    bom_chain, _ = self.lineage(bom)
                    imported, more = self.managed(bom_chain, self.properties(bom_chain))
                    for key, value in imported.items():
                        managed.setdefault(key, value)
                    unavailable.extend(more)
                    continue
                managed.setdefault(f"{group}:{artifact}", (version, dependency.scope))
        return managed, unavailable

    def declarations(self, pom: MavenPom) -> list[DeclaredDependency]:
        chain, missing_parent = self.lineage(pom)
        properties = self.properties(chain)
        managed, unavailable = self.managed(chain, properties)
        unknown_from = ", ".join(
            ([f"the parent {missing_parent}"] if missing_parent else [])
            + [f"the imported BOM {b}" for b in unavailable]
        )
        out: list[DeclaredDependency] = []
        seen: set[tuple[str, str]] = set()

        def declare(
            dependency: MavenDependency, field_name: str, conditions: tuple[str, ...]
        ) -> None:
            group = self.interpolate(dependency.group, properties)
            artifact = self.interpolate(dependency.artifact, properties)
            if not artifact:
                return
            name = f"{group}:{artifact}"
            # One artefact per name, classifier and type: the jar and the test-jar of a module
            # are two dependencies.
            identity = f"{name}:{dependency.classifier}:{dependency.type or 'jar'}"
            if (identity, field_name) in seen:
                return
            seen.add((identity, field_name))
            version = self.interpolate(dependency.version, properties)
            managed_version, managed_scope = managed.get(name, ("", ""))
            scope_text = dependency.scope or managed_scope or "compile"
            spec = version or managed_version
            note = None
            if not spec:
                spec = "*"
                note = (
                    f"the version is managed by {unknown_from}, which is not in the scanned tree"
                    if unknown_from
                    else "no version is declared or managed for it"
                )
            elif self.PLACEHOLDER.search(spec):
                note = f"the version {spec} uses a property no POM in the scanned tree defines"
            platform = list(conditions)
            if dependency.classifier:
                platform.append(f"classifier {dependency.classifier}")
            if dependency.type and dependency.type != "jar":
                platform.append(f"type {dependency.type}")
            out.append(
                DeclaredDependency(
                    name=name,
                    spec=spec,
                    scope=MavenEcosystem.SCOPES.get(scope_text, Scope.RUNTIME)
                    if not dependency.optional
                    else Scope.OPTIONAL,
                    field_name=field_name,
                    platform=tuple(platform),
                    exclusions=dependency.exclusions,
                    note=note,
                )
            )

        # What this POM itself declares. A parent's dependencies, profiles and plugins are
        # inherited by every module, but they are recorded once, against the POM that declares
        # them -- the parent is in the scan too -- rather than once per module.
        for dependency in pom.dependencies:
            declare(dependency, "dependency", ())
        for profile_id, trigger, dependencies, _ in pom.profiles:
            condition = f"profile {profile_id}" + (f" ({trigger})" if trigger else "")
            for dependency in dependencies:
                declare(dependency, f"profile {profile_id}", (condition,))
        for ancestor in (pom,):
            for group, artifact, version, _ in ancestor.plugins + ancestor.extensions:
                name = f"{self.interpolate(group, properties)}:{self.interpolate(artifact, properties)}"
                if (name, "plugin") in seen or not artifact:
                    continue
                seen.add((name, "plugin"))
                resolved = self.interpolate(version, properties)
                out.append(
                    DeclaredDependency(
                        name=name,
                        spec=resolved or "*",
                        scope=Scope.TOOL,
                        field_name="plugin",
                        note=None
                        if resolved
                        else "a build plugin with no version: Maven picks one from its own defaults",
                    )
                )
        return out


class MavenTree:
    """`mvn dependency:tree` output: the effective graph Maven resolved, supplied by the project.

    ```
      com.example:app:jar:1.0.0
      +- com.google.guava:guava:jar:33.3.1-jre:compile
      |  \\- com.google.guava:failureaccess:jar:1.0.2:compile
      \\- junit:junit:jar:4.13.2:test
    ```

    A POM declares; this is what resolved -- every transitive dependency, its scope, the version
    a range chose. When a build supplies it (`dependency-tree.txt`), it is read as the lockfile.
    """

    LINE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<indent>(?:[|+\\ ]  |[+\\]- )*)(?P<coords>[\w.\-]+:[\w.\-]+:[\w.\-]+(?::[\w.\-]+){1,3})(?P<rest>.*)$"
    )

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        lines = [line.rstrip() for line in content.text.splitlines() if line.strip()]
        lines = [re.sub(r"^\[INFO\] ", "", line) for line in lines]
        if not lines:
            return LockGraph(path=content.path, ecosystem=ecosystem)
        entries: list[LockEntry] = []
        parents: list[tuple[int, str]] = []
        children: dict[str, list[str]] = {}
        unreadable = 0
        for index, line in enumerate(lines):
            if index == 0:
                continue  # the project itself
            match = cls.LINE.match(line)
            if not match:
                unreadable += 1
                continue
            depth = len(match.group("indent")) // 3
            parts = match.group("coords").split(":")
            if len(parts) == 5:
                group, artifact, kind, version, scope = parts
                classifier = ""
            elif len(parts) == 6:
                group, artifact, kind, classifier, version, scope = parts
            else:
                unreadable += 1
                continue
            rest = match.group("rest")
            name = f"{group}:{artifact}"
            while parents and parents[-1][0] >= depth:
                parents.pop()
            key = f"{name}@{version}"
            if parents:
                children.setdefault(parents[-1][1], []).append(key)
            parents.append((depth, key))
            if "omitted for" in rest:
                continue
            platform = [f"classifier {classifier}"] if classifier else []
            if kind not in ("jar", "bundle"):
                platform.append(f"type {kind}")
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    scope=Scope.OPTIONAL
                    if "(optional)" in rest
                    else MavenEcosystem.SCOPES.get(scope, Scope.RUNTIME),
                    direct=depth == 0,
                    platform=tuple(platform),
                )
            )
        if unreadable and not entries:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} line(s) are not dependency:tree output",
            )
        entries = [
            LockEntry(
                name=e.name,
                version=e.version,
                scope=e.scope,
                direct=e.direct,
                platform=e.platform,
                dependencies=tuple(sorted(set(children.get(f"{e.name}@{e.version}", ())))),
            )
            for e in entries
        ]
        return LockGraph(
            path=content.path, ecosystem=ecosystem, entries=tuple(entries), integrity_elsewhere=True
        )


class MavenChecksums:
    """Maven Resolver's trusted checksums (`.mvn/checksums/checksums-<repository>.sha256`): the
    digest of every artefact a build resolved, recorded by Maven and committed so the next build
    refuses anything different.

    ```
      4bf0e2c5...4e90  com/google/guava/guava/33.3.1-jre/guava-33.3.1-jre.jar
    ```

    Lines are in the repository layout, so the coordinates are recovered from the path. The
    artefact of a dependency is its jar (or its classifier's jar); `.pom` lines, which every
    artefact has, are used only where nothing else was resolved. A companion: it completes the
    entries `dependency-tree.txt` resolved, for every module of the build below it.
    """

    # The digest field is taken as written and validated as a digest afterwards
    # (`Coordinate.integrity`): a value that is not one is kept as malformed and reported, never
    # skipped as if the line were absent.
    LINE: ClassVar[re.Pattern[str]] = re.compile(r"^(\S{1,256})\s+\*?(\S{1,1024})$")
    ALGORITHMS: ClassVar[dict[str, str]] = {
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
        "md5": "md5",
    }

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        algorithm = cls.ALGORITHMS.get(content.basename.rpartition(".")[2].lower())
        if algorithm is None:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="not a checksum summary file (.sha1, .sha256, .sha512)",
            )
        best: dict[tuple[str, str], tuple[int, str]] = {}
        unreadable = 0
        for raw in content.text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = cls.LINE.match(line)
            if not match:
                unreadable += 1
                continue
            digest, path = match.group(1).lower(), match.group(2)
            parts = path.split("/")
            if len(parts) < 4 or ".." in parts:
                unreadable += 1
                continue
            *group, artifact, version, filename = parts
            stem = f"{artifact}-{version}"
            if not filename.startswith(stem):
                unreadable += 1
                continue
            extension = filename.rpartition(".")[2]
            classified = filename[len(stem) :].startswith("-")
            # Prefer the plain jar, then a classified jar, then anything but a POM, then the POM.
            rank = (
                0
                if extension == "jar" and not classified
                else 1
                if extension == "jar"
                else 2
                if extension != "pom"
                else 3
            )
            key = (".".join(group) + ":" + artifact, version)
            if key not in best or rank < best[key][0]:
                best[key] = (rank, f"{algorithm}:{digest}")
        if unreadable and not best:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} line(s) are not '<digest>  <repository path>'",
            )
        entries = tuple(
            LockEntry(name=name, version=version, integrity=digest)
            for (name, version), (_, digest) in sorted(best.items())
        )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=entries,
            companion=True,
            companion_tree=True,
            owner_levels=2,
        )


class MavenWrapper:
    """`.mvn/wrapper/maven-wrapper.properties`: the Maven distribution the wrapper downloads and
    runs for every build, and whether its checksum is pinned."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        values: dict[str, str] = {}
        for raw in content.text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "!")) or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().replace("\\:", ":")
        declared: list[DeclaredDependency] = []
        url = values.get("distributionUrl", "")
        found = re.search(r"apache-maven/([\w.\-]+)/apache-maven-[\w.\-]+\.zip$", url)
        if not found:
            # The one thing the file is for. Without it the wrapper cannot run, and an empty
            # result would read as "this build uses no tool".
            return BaseEcosystem._err(
                content,
                ecosystem,
                "no readable distributionUrl naming an apache-maven-<version> distribution"
                if url
                else "no distributionUrl: the wrapper names no Maven distribution",
            )
        if found:
            declared.append(
                DeclaredDependency(
                    name="org.apache.maven:apache-maven",
                    spec=found.group(1),
                    scope=Scope.TOOL,
                    field_name="distributionUrl",
                    source=url,
                )
            )
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=tuple(declared))


class MavenEcosystem(BaseEcosystem):
    id = "maven"
    purl_type = "maven"
    manifest_globs: tuple[str, ...] = ("**/pom.xml", "**/.mvn/wrapper/maven-wrapper.properties")
    lockfile_globs: tuple[str, ...] = (
        "**/dependency-tree.txt",
        "**/.mvn/checksums/*.sha1",
        "**/.mvn/checksums/*.sha256",
        "**/.mvn/checksums/*.sha512",
    )
    registry_hosts: frozenset[str] = frozenset(
        {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"}
    )
    records_integrity = False
    """A POM records no hashes, and `dependency-tree.txt` none either. A build that commits
    Maven Resolver's trusted checksums (`.mvn/checksums/`) has them, and they are applied to the
    resolved entries; with `--online` they are compared with Maven Central's own."""
    integrity_companion = True

    SCOPES: ClassVar[dict[str, Scope]] = {
        "compile": Scope.RUNTIME,
        "runtime": Scope.RUNTIME,
        "provided": Scope.BUILD,
        "system": Scope.BUILD,
        "test": Scope.TEST,
    }

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """`?classifier=linux-x86_64&type=test-jar`: the jar and the test-jar of one version, or
        a native classifier beside the plain jar, are different artefacts with different bytes."""
        found = {}
        for condition in platform:
            kind, _, value = condition.partition(" ")
            if kind in ("classifier", "type") and value and " " not in value:
                found[kind] = value
        return ("?" + "&".join(f"{k}={v}" for k, v in sorted(found.items()))) if found else ""

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A POM resolved against the other POMs of its build, when they are in the scan.

        Read structurally (`core/safexml.py`): a DTD or entity declaration is refused, never
        expanded, and a POM that is not well-formed XML is a parse error, not an empty build."""
        if content.basename == "maven-wrapper.properties":
            return MavenWrapper.parse(content, self.id)
        poms: dict[str, MavenPom] = {}
        for path, other in files.items():
            if other.basename != "pom.xml":
                continue
            try:
                poms[path] = MavenPom(path, SafeXml.parse(other.text, source=path))
            except SafeXmlError as exc:
                if path == content.path:
                    return BaseEcosystem._err(content, self.id, f"not a readable POM: {exc}")
        pom = poms.get(content.path)
        if pom is None:
            return BaseEcosystem._err(content, self.id, "not a readable POM")
        build = MavenBuild(poms)
        sources = tuple(f"repository {rid or '?'}: {url}" for rid, url in pom.repositories if url)
        properties = build.properties(build.lineage(pom)[0])
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=f"{build.interpolate(pom.group, properties)}:{pom.artifact}"
            if pom.artifact
            else None,
            version=build.interpolate(pom.version, properties) or None,
            dependencies=tuple(build.declarations(pom)),
            sources=sources,
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "dependency-tree.txt":
            return MavenTree.parse(content, self.id)
        if "/.mvn/checksums/" in f"/{content.path}":
            return MavenChecksums.parse(content, self.id)
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            parse_error=(
                "Maven has no standard lockfile: supply `mvn dependency:tree -DoutputFile=dependency-tree.txt` "
                "output, and commit trusted checksums under .mvn/checksums/"
            ),
        )


__all__ = [
    "BazelEcosystem",
    "CargoEcosystem",
    "CocoaPodsEcosystem",
    "ComposerEcosystem",
    "ConanEcosystem",
    "CondaEcosystem",
    "CranEcosystem",
    "GitHubActionsEcosystem",
    "GoEcosystem",
    "GradleEcosystem",
    "HexEcosystem",
    "MavenEcosystem",
    "NuGetEcosystem",
    "PubEcosystem",
    "RubyGemsEcosystem",
    "SwiftEcosystem",
]
