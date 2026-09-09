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

import json
import re
import tomllib
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------


class CargoEcosystem(BaseEcosystem):
    id = "cargo"
    purl_type = "cargo"
    manifest_globs: tuple[str, ...] = ("**/Cargo.toml",)
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

    def parse_manifest(self, content: FileContent) -> Manifest:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, self.id, f"invalid TOML: {exc}")

        declared: list[DeclaredDependency] = []
        for section, scope in (
            ("dependencies", Scope.RUNTIME),
            ("dev-dependencies", Scope.DEV),
            ("build-dependencies", Scope.BUILD),
        ):
            for name, spec in (data.get(section) or {}).items():
                text = spec if isinstance(spec, str) else BaseEcosystem._table_spec(spec)
                declared.append(
                    DeclaredDependency(name=str(name), spec=text, scope=scope, field_name=section)
                )

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
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )
        entries = [
            LockEntry(
                name=str(pkg.get("name", "")),
                version=str(pkg.get("version", "")),
                integrity=BaseEcosystem._s(pkg.get("checksum")),
                resolved_from=BaseEcosystem._s(pkg.get("source")),
                dependencies=tuple(sorted(d.split()[0] for d in pkg.get("dependencies") or [])),
            )
            for pkg in data.get("package") or []
            if isinstance(pkg, dict) and pkg.get("name")
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------


class GoEcosystem(BaseEcosystem):
    id = "gomod"
    purl_type = "golang"
    manifest_globs: tuple[str, ...] = ("**/go.mod",)
    lockfile_globs: tuple[str, ...] = ("**/go.sum",)
    registry_hosts: frozenset[str] = frozenset({"proxy.golang.org", "sum.golang.org"})

    _REQUIRE = re.compile(r"^\s*([^\s()]+)\s+(v[^\s/]+)")
    _REPLACE = re.compile(r"^\s*replace\s+(\S+)\s+=>\s+(\S+)")

    def normalize_name(self, name: str) -> str:
        """Go module paths are case-sensitive but case-encoded in the proxy.

        Lowercased for comparison only. Two paths differing solely in case are a
        classic confusion vector, so they must compare equal for typosquat
        purposes even though they are distinct modules.
        """
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        hooks: list[Hook] = []
        module: str | None = None
        in_require = False

        for raw in content.text.splitlines():
            line = raw.split("//", 1)[0].rstrip()
            stripped = line.strip()
            if stripped.startswith("module "):
                module = stripped.split(None, 1)[1].strip()
                continue
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue

            replace = self._REPLACE.match(stripped)
            if replace:
                # A replace directive redirects a module elsewhere, commonly to
                # a local path or a fork. It silently changes what compiles into
                # the binary while the import path stays identical, so it is
                # recorded as a non-registry source.
                declared.append(
                    DeclaredDependency(
                        name=replace.group(1),
                        spec=replace.group(2),
                        scope=Scope.RUNTIME,
                        field_name="replace",
                    )
                )
                continue

            target = stripped
            if stripped.startswith("require "):
                target = stripped[len("require ") :]
            elif not in_require:
                continue

            match = self._REQUIRE.match(target)
            if match:
                declared.append(
                    DeclaredDependency(
                        name=match.group(1),
                        spec=match.group(2),
                        scope=Scope.RUNTIME,
                        field_name="require",
                    )
                )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=module,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        """go.sum records a hash per module version.

        Not a resolution graph, but it is the integrity record, which is the
        part that matters here: a module version present in go.mod with no
        corresponding go.sum entry is unverified.
        """
        seen: dict[tuple[str, str], str] = {}
        for raw in content.text.splitlines():
            parts = raw.split()
            if len(parts) != 3:
                continue
            name, version, digest = parts
            version = version.removesuffix("/go.mod")
            seen.setdefault((name, version), digest)
        entries = [
            LockEntry(name=name, version=version, integrity=digest)
            for (name, version), digest in sorted(seen.items())
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Maven and Gradle
# ---------------------------------------------------------------------------


class MavenEcosystem(BaseEcosystem):
    id = "maven"
    purl_type = "maven"
    manifest_globs: tuple[str, ...] = ("**/pom.xml",)
    lockfile_globs: tuple[str, ...] = ()
    registry_hosts: frozenset[str] = frozenset(
        {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"}
    )

    _DEP = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL | re.IGNORECASE)
    _TAG = re.compile(r"<(groupId|artifactId|version|scope)>\s*([^<]*)\s*</\1>", re.IGNORECASE)
    _REPO = re.compile(r"<url>\s*([^<]+?)\s*</url>", re.IGNORECASE)

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        """Read a POM with regular expressions rather than an XML parser.

        Deliberate. Python's XML parsers carry documented hazards on untrusted
        input -- entity expansion, external entity resolution, quadratic blowup
        -- and a POM is attacker-controlled like everything else in the target.
        The fields needed here are simple and flat, so pattern extraction avoids
        the entire class of problem rather than mitigating it.
        """
        text = content.text
        declared: list[DeclaredDependency] = []

        for block in self._DEP.findall(text):
            fields = {k.lower(): v for k, v in self._TAG.findall(block)}
            group = fields.get("groupid", "").strip()
            artifact = fields.get("artifactid", "").strip()
            if not artifact:
                continue
            scope_text = fields.get("scope", "compile").strip().lower()
            declared.append(
                DeclaredDependency(
                    name=f"{group}:{artifact}" if group else artifact,
                    spec=fields.get("version", "").strip() or "*",
                    scope=Scope.TEST if scope_text == "test" else Scope.RUNTIME,
                    field_name="dependency",
                )
            )

        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            parse_error="Maven has no standard lockfile",
        )


class GradleEcosystem(BaseEcosystem):
    id = "gradle"
    purl_type = "maven"
    manifest_globs: tuple[str, ...] = ("**/build.gradle", "**/build.gradle.kts")
    lockfile_globs: tuple[str, ...] = ("**/gradle.lockfile",)
    registry_hosts: frozenset[str] = frozenset(
        {"repo.maven.apache.org", "repo1.maven.org", "jcenter.bintray.com"}
    )

    _DEP = re.compile(
        r"""(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|
            testCompile|annotationProcessor|kapt)
            \s*[\s(]\s*["']([^"':]+):([^"':]+):?([^"']*)["']""",
        re.VERBOSE,
    )

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared = [
            DeclaredDependency(
                name=f"{group}:{artifact}",
                spec=version or "*",
                scope=Scope.RUNTIME,
                field_name="dependencies",
            )
            for group, artifact, version in self._DEP.findall(content.text)
        ]
        # A Gradle build file is executable Groovy or Kotlin, evaluated on every
        # build. It is a build hook by nature, not only when it declares one.
        hooks = (
            Hook(
                kind="build",
                path=content.path,
                name=content.basename,
                command="gradle build",
                ecosystem=self.id,
            ),
        )
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            dependencies=tuple(declared),
            hooks=hooks,
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        entries: list[LockEntry] = []
        for raw in content.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            coordinate = line.split("=", 1)[0]
            parts = coordinate.split(":")
            if len(parts) >= 3:
                entries.append(LockEntry(name=f"{parts[0]}:{parts[1]}", version=parts[2]))
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------


class NuGetEcosystem(BaseEcosystem):
    id = "nuget"
    purl_type = "nuget"
    manifest_globs: tuple[str, ...] = (
        "**/*.csproj",
        "**/*.fsproj",
        "**/*.vbproj",
        "**/packages.config",
    )
    lockfile_globs: tuple[str, ...] = ("**/packages.lock.json",)
    registry_hosts: frozenset[str] = frozenset({"api.nuget.org", "nuget.org"})

    _PKGREF = re.compile(
        r'<PackageReference\s+Include="([^"]+)"(?:[^>]*?Version="([^"]*)")?', re.IGNORECASE
    )
    _PKG = re.compile(r'<package\s+id="([^"]+)"\s+version="([^"]*)"', re.IGNORECASE)

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        text = content.text
        declared = [
            DeclaredDependency(name=name, spec=version or "*", field_name="PackageReference")
            for name, version in self._PKGREF.findall(text)
        ]
        declared += [
            DeclaredDependency(name=name, spec=version or "*", field_name="packages.config")
            for name, version in self._PKG.findall(text)
        ]
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )
        entries: list[LockEntry] = []
        for framework in (data.get("dependencies") or {}).values():
            if not isinstance(framework, dict):
                continue
            for name, meta in sorted(framework.items()):
                if not isinstance(meta, dict):
                    continue
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("resolved", "")),
                        integrity=BaseEcosystem._s(meta.get("contentHash")),
                        direct=str(meta.get("type", "")).lower() == "direct",
                    )
                )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------


class ComposerEcosystem(BaseEcosystem):
    id = "composer"
    purl_type = "composer"
    manifest_globs: tuple[str, ...] = ("**/composer.json",)
    lockfile_globs: tuple[str, ...] = ("**/composer.lock",)
    registry_hosts: frozenset[str] = frozenset({"packagist.org", "repo.packagist.org"})

    lifecycle_keys = frozenset(
        {
            "pre-install-cmd",
            "post-install-cmd",
            "pre-update-cmd",
            "post-update-cmd",
            "post-autoload-dump",
            "post-root-package-install",
            "post-create-project-cmd",
        }
    )

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, self.id, f"invalid JSON: {exc}")

        declared: list[DeclaredDependency] = []
        for section, scope in (("require", Scope.RUNTIME), ("require-dev", Scope.DEV)):
            for name, spec in sorted((data.get(section) or {}).items()):
                if str(name).startswith("php") or str(name).startswith("ext-"):
                    continue
                declared.append(
                    DeclaredDependency(
                        name=str(name), spec=str(spec), scope=scope, field_name=section
                    )
                )

        scripts = data.get("scripts")
        hooks: tuple[Hook, ...] = ()
        if isinstance(scripts, dict):
            flat = {
                k: (" && ".join(str(x) for x in v) if isinstance(v, list) else str(v))
                for k, v in scripts.items()
            }
            hooks = tuple(self.lifecycle_hooks(flat, content.path))

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=BaseEcosystem._s(data.get("name")),
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
            hooks=hooks,
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )
        entries: list[LockEntry] = []
        for section, scope in (
            ("packages", Scope.RUNTIME),
            ("packages-dev", Scope.DEV),
        ):
            for pkg in data.get(section) or []:
                if not isinstance(pkg, dict):
                    continue
                dist = pkg.get("dist") or {}
                entries.append(
                    LockEntry(
                        name=str(pkg.get("name", "")),
                        version=str(pkg.get("version", "")),
                        integrity=BaseEcosystem._s(dist.get("shasum")),
                        resolved_from=BaseEcosystem._s(dist.get("url")),
                        scope=scope,
                        dependencies=tuple(sorted((pkg.get("require") or {}).keys())),
                    )
                )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------


class RubyGemsEcosystem(BaseEcosystem):
    id = "rubygems"
    purl_type = "gem"
    manifest_globs: tuple[str, ...] = ("**/Gemfile", "**/*.gemspec")
    lockfile_globs: tuple[str, ...] = ("**/Gemfile.lock",)
    registry_hosts: frozenset[str] = frozenset({"rubygems.org", "index.rubygems.org"})

    _GEM = re.compile(r"""^\s*gem\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?""", re.M)
    # re.M is load-bearing: without it `^` matches only at the start of the
    # file, the pattern finds nothing, and an empty graph looks exactly like a
    # project with no dependencies.
    _LOCK = re.compile(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", re.M)

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared = [
            DeclaredDependency(name=name, spec=spec or "*", field_name="gem")
            for name, spec in self._GEM.findall(content.text)
        ]
        hooks: list[Hook] = []
        if content.basename.endswith(".gemspec"):
            # A gemspec is executable Ruby, evaluated whenever the gem is built
            # or installed from source.
            hooks.append(
                Hook(
                    kind="build",
                    path=content.path,
                    name=content.basename,
                    ecosystem=self.id,
                )
            )
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        entries = [
            LockEntry(name=name, version=version)
            for name, version in self._LOCK.findall(content.text)
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# CocoaPods and pub
# ---------------------------------------------------------------------------


class CocoaPodsEcosystem(BaseEcosystem):
    id = "cocoapods"
    purl_type = "cocoapods"
    manifest_globs: tuple[str, ...] = ("**/Podfile", "**/*.podspec")
    lockfile_globs: tuple[str, ...] = ("**/Podfile.lock",)
    registry_hosts: frozenset[str] = frozenset({"cdn.cocoapods.org", "github.com/CocoaPods"})

    _POD = re.compile(r"""^\s*pod\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?""", re.M)
    # See the note on the RubyGems lockfile pattern: re.M is required.
    _LOCK = re.compile(r"^\s{2}-\s+([A-Za-z0-9_.\-/+]+)\s+\(([^)]+)\)", re.M)

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared = [
            DeclaredDependency(name=name, spec=spec or "*", field_name="pod")
            for name, spec in self._POD.findall(content.text)
        ]
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        entries = [
            LockEntry(name=name, version=version)
            for name, version in self._LOCK.findall(content.text)
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


class PubEcosystem(BaseEcosystem):
    id = "pub"
    purl_type = "pub"
    manifest_globs: tuple[str, ...] = ("**/pubspec.yaml",)
    lockfile_globs: tuple[str, ...] = ("**/pubspec.lock",)
    registry_hosts: frozenset[str] = frozenset({"pub.dev", "pub.dartlang.org"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        from cordon_scanner.core.config import RestrictedYamlParser

        try:
            data = RestrictedYamlParser._load_yaml_subset(content.text, source=content.path)
        except Exception as exc:
            return BaseEcosystem._err(content, self.id, f"invalid YAML: {exc}")

        declared: list[DeclaredDependency] = []
        for section, scope in (
            ("dependencies", Scope.RUNTIME),
            ("dev_dependencies", Scope.DEV),
        ):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, spec in sorted(block.items()):
                text = spec if isinstance(spec, str) else BaseEcosystem._table_spec(spec)
                declared.append(
                    DeclaredDependency(name=str(name), spec=text, scope=scope, field_name=section)
                )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=BaseEcosystem._s(data.get("name")),
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        from cordon_scanner.core.config import RestrictedYamlParser

        try:
            data = RestrictedYamlParser._load_yaml_subset(content.text, source=content.path)
        except Exception as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid YAML: {exc}"
            )
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return LockGraph(path=content.path, ecosystem=self.id)
        entries = [
            LockEntry(
                name=str(name),
                version=str(meta.get("version", "")),
                resolved_from=BaseEcosystem._s((meta.get("description") or {}).get("url"))
                if isinstance(meta.get("description"), dict)
                else None,
                scope=Scope.DEV
                if str(meta.get("dependency", "")).startswith("direct dev")
                else Scope.RUNTIME,
                direct=str(meta.get("dependency", "")).startswith("direct"),
            )
            for name, meta in sorted(packages.items())
            if isinstance(meta, dict)
        ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


__all__ = [
    "CargoEcosystem",
    "CocoaPodsEcosystem",
    "ComposerEcosystem",
    "GoEcosystem",
    "GradleEcosystem",
    "MavenEcosystem",
    "NuGetEcosystem",
    "PubEcosystem",
    "RubyGemsEcosystem",
]
