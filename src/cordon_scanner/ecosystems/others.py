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
from typing import TYPE_CHECKING, Any

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
                # No `source` means a workspace member or a path dependency: the
                # crate is in this repository. Cargo writes no checksum for those
                # because there is nothing to check against.
                local=not BaseEcosystem._s(pkg.get("source")),
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

    _MANAGEMENT = re.compile(
        r"<dependencyManagement>(.*?)</dependencyManagement>", re.DOTALL | re.IGNORECASE
    )
    _PROPERTIES = re.compile(r"<properties>(.*?)</properties>", re.DOTALL | re.IGNORECASE)
    _PROPERTY = re.compile(r"<([A-Za-z0-9_.\-]+)>\s*([^<]*?)\s*</\1>")
    _PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_.\-]+)\}")
    _PARENT = re.compile(r"<parent>(.*?)</parent>", re.DOTALL | re.IGNORECASE)
    #: How many times a property may expand into another before the parser
    #: stops. Maven allows `${a}` to resolve to `${b}`; a POM that resolves in
    #: a cycle is a file the parser must leave rather than spin on.
    _MAX_PROPERTY_DEPTH = 5

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    @classmethod
    def _managed_versions(cls, text: str, properties: dict[str, str]) -> dict[str, str]:
        """`group:artifact` -> version, from every `<dependencyManagement>` block.

        These are the versions a dependency inherits when it declares none, and
        stating them once is how a multi-module build is meant to be written.
        """
        managed: dict[str, str] = {}
        for section in cls._MANAGEMENT.findall(text):
            for block in cls._DEP.findall(section):
                fields = {k.lower(): v for k, v in cls._TAG.findall(block)}
                artifact = cls._resolve(fields.get("artifactid", "").strip(), properties)
                if not artifact:
                    continue
                group = cls._resolve(fields.get("groupid", "").strip(), properties)
                version = cls._resolve(fields.get("version", "").strip(), properties)
                if version:
                    managed[f"{group}:{artifact}" if group else artifact] = version
        return managed

    @classmethod
    def _own_coordinates(cls, text: str) -> dict[str, str]:
        """The project's own groupId, artifactId and version.

        Read from the header alone -- everything before the first
        `<dependencies>`, with any `<parent>` block removed. Scanning the whole
        document instead takes whichever coordinate appears last, which is a
        dependency's, so a POM reported its final dependency's artifactId as
        the project's name.

        groupId and version fall back to the parent's, because a module that
        inherits them omits its own, and that inheritance is what
        `${project.version}` resolves against.
        """
        lowered = text.lower()
        cut = lowered.find("<dependencies")
        header = text[:cut] if cut != -1 else text

        parent = cls._PARENT.search(header)
        body = header[: parent.start()] + header[parent.end() :] if parent else header
        own = {k.lower(): v.strip() for k, v in cls._TAG.findall(body)}
        inherited = (
            {k.lower(): v.strip() for k, v in cls._TAG.findall(parent.group(1))} if parent else {}
        )
        return {
            "groupid": own.get("groupid") or inherited.get("groupid", ""),
            "artifactid": own.get("artifactid", ""),
            "version": own.get("version") or inherited.get("version", ""),
        }

    @classmethod
    def _properties_of(cls, text: str) -> dict[str, str]:
        """Every `<properties>` entry, plus the project coordinates Maven
        predefines.

        A POM that writes `<version>${spring.version}</version>` is pinned; it
        just says so one block higher up. Reading the placeholder literally put
        `${spring.version}` into the purl and into every finding about that
        dependency, so the version was neither usable nor true.

        `${project.version}` and its `${pom.*}` aliases are resolved from the
        project's own version, or from the parent's where the project inherits
        one, which is the commonest placeholder in a multi-module build.
        """
        values: dict[str, str] = {}
        for block in cls._PROPERTIES.findall(text):
            for name, value in cls._PROPERTY.findall(block):
                values[name] = value

        own = cls._own_coordinates(text)
        version = own["version"]
        if version and not cls._PLACEHOLDER.search(version):
            for alias in ("project.version", "pom.version", "version"):
                values.setdefault(alias, version)
        if own["groupid"]:
            for alias in ("project.groupId", "pom.groupId"):
                values.setdefault(alias, own["groupid"])
        if own["artifactid"]:
            for alias in ("project.artifactId", "pom.artifactId"):
                values.setdefault(alias, own["artifactid"])
        return values

    @classmethod
    def _resolve(cls, value: str, properties: dict[str, str]) -> str:
        """Expand `${...}` against `properties`, leaving anything unknown alone.

        An unresolved placeholder is left verbatim rather than blanked: it is
        the honest record of a version this file does not determine, and the
        rules that read a spec can then say so instead of treating it as a
        pin they verified.
        """
        for _ in range(cls._MAX_PROPERTY_DEPTH):
            if not cls._PLACEHOLDER.search(value):
                return value
            expanded = cls._PLACEHOLDER.sub(lambda m: properties.get(m.group(1), m.group(0)), value)
            if expanded == value:
                return value
            value = expanded
        return value

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
        properties = self._properties_of(text)
        managed = self._managed_versions(text, properties)

        # `<dependencyManagement>` states versions for the whole tree and the
        # dependencies themselves then omit them. Reading only `<dependencies>`
        # meant every dependency in a project that centralises its versions --
        # the recommended Maven layout -- reached the graph with no version, so
        # no advisory could match it. The block is removed before the scan so
        # its own entries are not reported as dependencies in their own right.
        body = self._MANAGEMENT.sub("", text)

        for block in self._DEP.findall(body):
            fields = {k.lower(): v for k, v in self._TAG.findall(block)}
            group = self._resolve(fields.get("groupid", "").strip(), properties)
            artifact = self._resolve(fields.get("artifactid", "").strip(), properties)
            if not artifact:
                continue
            scope_text = fields.get("scope", "compile").strip().lower()
            name = f"{group}:{artifact}" if group else artifact
            version = self._resolve(fields.get("version", "").strip(), properties)
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=version or managed.get(name, "") or "*",
                    scope=Scope.TEST if scope_text == "test" else Scope.RUNTIME,
                    field_name="dependency",
                )
            )

        own = self._own_coordinates(text)
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=self._resolve(own["artifactid"], properties) or None,
            version=self._resolve(own["version"], properties) or None,
            dependencies=tuple(declared),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            parse_error="Maven has no standard lockfile",
        )


class GradleEcosystem(BaseEcosystem):
    id = "gradle"
    purl_type = "maven"
    manifest_globs: tuple[str, ...] = (
        "**/build.gradle",
        "**/build.gradle.kts",
        "**/gradle/libs.versions.toml",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/gradle.lockfile",
        "**/gradle/verification-metadata.xml",
    )
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
        if content.basename == "libs.versions.toml":
            return self._parse_version_catalog(content)
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
        if content.basename == "verification-metadata.xml":
            return self._parse_verification_metadata(content)
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

    def _parse_version_catalog(self, content: FileContent) -> Manifest:
        """`gradle/libs.versions.toml`, Gradle's central version declaration.

        A catalog states each coordinate once and every module then refers to it
        by alias, so a build using one has almost nothing in its `build.gradle`
        for the regex above to find. Without this, the projects following
        Gradle's current recommendation were the ones with no dependency graph.
        """
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, self.id, f"invalid TOML: {exc}")

        versions = {
            str(k): str(v) for k, v in (data.get("versions") or {}).items() if isinstance(v, str)
        }
        declared: list[DeclaredDependency] = []
        for alias, entry in (data.get("libraries") or {}).items():
            name, spec = self._catalog_coordinate(entry, versions)
            if name:
                declared.append(
                    DeclaredDependency(name=name, spec=spec or "*", field_name=f"libraries.{alias}")
                )
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    @staticmethod
    def _catalog_coordinate(entry: object, versions: dict[str, str]) -> tuple[str, str]:
        """One `[libraries]` entry as `(group:artifact, version)`.

        Three spellings are legal: a `"group:artifact:version"` string, a table
        with `module`, or a table with separate `group` and `name`. The version
        is inline, or a `version.ref` naming a `[versions]` key, or a rich
        table with `require`/`strictly`/`prefer`.
        """
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) >= 3:
                return (f"{parts[0]}:{parts[1]}", parts[2])
            return (f"{parts[0]}:{parts[1]}", "") if len(parts) == 2 else ("", "")
        if not isinstance(entry, dict):
            return ("", "")

        module = entry.get("module")
        if isinstance(module, str) and ":" in module:
            name = module
        else:
            group, artifact = entry.get("group"), entry.get("name")
            if not (isinstance(group, str) and isinstance(artifact, str)):
                return ("", "")
            name = f"{group}:{artifact}"

        version = entry.get("version")
        if isinstance(version, str):
            return (name, version)
        if isinstance(version, dict):
            ref = version.get("ref")
            if isinstance(ref, str):
                return (name, versions.get(ref, ""))
            for key in ("require", "strictly", "prefer"):
                if isinstance(version.get(key), str):
                    return (name, str(version[key]))
        return (name, "")

    _VERIFY_COMPONENT = re.compile(
        r'<component\s+group="([^"]+)"\s+name="([^"]+)"\s+version="([^"]+)"(.*?)</component>',
        re.DOTALL | re.IGNORECASE,
    )
    _VERIFY_SHA = re.compile(r'<(sha256|sha512|sha1|md5)\s+value="([0-9a-fA-F]+)"', re.IGNORECASE)

    def _parse_verification_metadata(self, content: FileContent) -> LockGraph:
        """`gradle/verification-metadata.xml` -- Gradle dependency verification.

        The only place a Gradle build records an artefact hash, which makes it
        the only Gradle file able to answer the integrity rules. Read with
        patterns rather than an XML parser, for the reason the Maven parser
        gives: the file is attacker-controlled like everything else in the
        target, and Python's XML parsers carry documented hazards on that input.
        """
        entries: list[LockEntry] = []
        for group, name, version, body in self._VERIFY_COMPONENT.findall(content.text):
            digest = self._VERIFY_SHA.search(body)
            entries.append(
                LockEntry(
                    name=f"{group}:{name}",
                    version=version,
                    integrity=f"{digest.group(1).lower()}:{digest.group(2).lower()}"
                    if digest
                    else None,
                )
            )
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
    lockfile_globs: tuple[str, ...] = ("**/packages.lock.json", "**/project.assets.json")
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
        if content.basename == "project.assets.json":
            return self._parse_assets(content, data)
        entries: list[LockEntry] = []
        for framework in (data.get("dependencies") or {}).values():
            if not isinstance(framework, dict):
                continue
            for name, meta in sorted(framework.items()):
                if not isinstance(meta, dict):
                    continue
                kind = str(meta.get("type", "")).lower()
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("resolved", "")),
                        integrity=BaseEcosystem._s(meta.get("contentHash")),
                        direct=kind == "direct",
                        # `"type": "Project"` is a reference to another project in the
                        # same solution. It has no `contentHash` because there is
                        # nothing to fetch -- the bytes are in the repository -- which
                        # is the same statement npm makes with `"link": true` and Cargo
                        # makes by omitting `source`.
                        #
                        # `bitwarden/server` is a .NET solution of about forty projects
                        # that reference each other, so every `packages.lock.json` in it
                        # lists several: 73 of its 86 blocking findings, and the single
                        # largest group in the repository.
                        local=kind == "project",
                    )
                )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    def _parse_assets(self, content: FileContent, data: dict[str, Any]) -> LockGraph:
        """`project.assets.json`, which is what a restored .NET project has.

        `packages.lock.json` exists only when a project opted into locking;
        `obj/project.assets.json` is written by every `dotnet restore`. Reading
        only the first meant the ordinary .NET project had no dependency graph.

        `libraries` carries the resolved set keyed `Name/Version`, and `targets`
        carries the edges per framework.
        """
        entries: list[LockEntry] = []
        direct: set[str] = set()
        for group in (data.get("projectFileDependencyGroups") or {}).values():
            if isinstance(group, list):
                direct.update(str(d).split(" ", 1)[0].lower() for d in group)

        edges: dict[str, tuple[str, ...]] = {}
        for target in (data.get("targets") or {}).values():
            if not isinstance(target, dict):
                continue
            for key, meta in target.items():
                if not isinstance(meta, dict):
                    continue
                name = str(key).split("/", 1)[0]
                dependencies = meta.get("dependencies")
                if isinstance(dependencies, dict):
                    edges[name] = tuple(sorted(str(d) for d in dependencies))

        for key, meta in (data.get("libraries") or {}).items():
            if not isinstance(meta, dict):
                continue
            name, _, version = str(key).partition("/")
            if not name or str(meta.get("type", "package")).lower() == "project":
                continue
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=BaseEcosystem._s(meta.get("sha512")),
                    dependencies=edges.get(name, ()),
                    direct=name.lower() in direct,
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


# ---------------------------------------------------------------------------
# Swift
# ---------------------------------------------------------------------------


class SwiftEcosystem(BaseEcosystem):
    """Swift Package Manager.

    A Swift dependency is a git URL rather than a registry name, so the purl
    identity is the repository it resolves from. `Package.resolved` is the only
    file that records a revision, and a revision is what a scan can act on: the
    manifest states a range, and `Package.swift` is Swift source that would have
    to be compiled to read properly -- which is the same argument `setup.py`
    gets, and the same answer.
    """

    id = "swift"
    purl_type = "swift"
    manifest_globs: tuple[str, ...] = ("**/Package.swift",)
    lockfile_globs: tuple[str, ...] = ("**/Package.resolved",)
    registry_hosts: frozenset[str] = frozenset(
        {"github.com", "gitlab.com", "swiftpackageindex.com"}
    )

    _PACKAGE = re.compile(r'\.package\s*\(\s*url:\s*"([^"]+)"([^)]*)\)', re.DOTALL)
    _REQUIREMENT = re.compile(r'"([0-9][^"]*)"')

    def normalize_name(self, name: str) -> str:
        return name.strip().lower().removesuffix(".git")

    @staticmethod
    def _identity(location: str) -> str:
        """A package's name: the repository path it resolves from.

        `swiftlang/swift-nio` rather than `NIO`, because the display name is
        chosen by whoever depends on it and two packages may share one.
        """
        text = location.strip().removesuffix(".git")
        if "://" in text:
            text = text.split("://", 1)[1]
        text = text.rpartition("@")[2]
        parts = [p for p in text.replace(":", "/").split("/") if p]
        return "/".join(parts[-2:]) if len(parts) >= 2 else text

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        for url, requirement in self._PACKAGE.findall(content.text):
            version = self._REQUIREMENT.search(requirement)
            declared.append(
                DeclaredDependency(
                    name=self._identity(url),
                    spec=version.group(1) if version else "*",
                    field_name="package",
                )
            )
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )

        # Version 1 nests under `object.pins`; version 2 and 3 put `pins` at the
        # top and renamed `repositoryURL` to `location`. All three are in use.
        pins = data.get("pins")
        if not isinstance(pins, list):
            pins = (data.get("object") or {}).get("pins")
        if not isinstance(pins, list):
            return LockGraph(path=content.path, ecosystem=self.id)

        entries: list[LockEntry] = []
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            location = BaseEcosystem._s(pin.get("location")) or BaseEcosystem._s(
                pin.get("repositoryURL")
            )
            name = self._identity(location) if location else BaseEcosystem._s(pin.get("identity"))
            state = pin.get("state") or {}
            if not name or not isinstance(state, dict):
                continue
            entries.append(
                LockEntry(
                    name=name,
                    # A branch pin has a revision and no version, and the
                    # revision is the only thing that identifies what was built.
                    version=str(state.get("version") or state.get("revision") or ""),
                    resolved_from=location,
                    direct=True,
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Hex (Elixir and Erlang)
# ---------------------------------------------------------------------------


class HexEcosystem(BaseEcosystem):
    """Hex, via `mix.lock`.

    `mix.exs` is Elixir source and is read for declarations only; `mix.lock` is
    a literal map of resolved packages and is where the versions and hashes are.
    """

    id = "hex"
    purl_type = "hex"
    manifest_globs: tuple[str, ...] = ("**/mix.exs",)
    lockfile_globs: tuple[str, ...] = ("**/mix.lock",)
    registry_hosts: frozenset[str] = frozenset({"hex.pm", "repo.hex.pm"})

    # `:name` or `:"name-with-hyphens"`. A hex package name may contain a
    # hyphen, and a hyphen is not legal in a bare Elixir atom -- mix writes
    # those quoted. Matching only the bare form made every dependency on such a
    # package invisible: `ecdsa-elixir` has a published advisory and a
    # `mix.lock` pinning it reported nothing at all.
    _DEP = re.compile(r'\{\s*:(?:"([a-z_0-9.-]+)"|([a-z_0-9]+))\s*,\s*"([^"]+)"')
    _LOCK = re.compile(
        r'"([a-z_0-9.-]+)"\s*:\s*\{\s*:hex\s*,\s*'
        r':(?:"[a-z_0-9.-]+"|[a-z_0-9]+)\s*,\s*"([^"]+)"([^}]*)\}',
        re.DOTALL,
    )
    _LOCK_HASH = re.compile(r'"([0-9a-f]{64})"')

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared = [
            # Two name groups, one for the quoted atom and one for the bare
            # form; exactly one of them matched.
            DeclaredDependency(name=quoted or bare, spec=spec, field_name="deps")
            for quoted, bare, spec in self._DEP.findall(content.text)
        ]
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        entries: list[LockEntry] = []
        for name, version, tail in self._LOCK.findall(content.text):
            digest = self._LOCK_HASH.search(tail)
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=f"sha256:{digest.group(1)}" if digest else None,
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# CRAN (R)
# ---------------------------------------------------------------------------


class CranEcosystem(BaseEcosystem):
    """CRAN, via `DESCRIPTION` and `renv.lock`.

    `renv.lock` is the only R file that records what was actually installed;
    `DESCRIPTION` states ranges, in a comma-separated field that wraps across
    lines.
    """

    id = "cran"
    purl_type = "cran"
    manifest_globs: tuple[str, ...] = ("**/DESCRIPTION",)
    lockfile_globs: tuple[str, ...] = ("**/renv.lock",)
    registry_hosts: frozenset[str] = frozenset({"cran.r-project.org", "cloud.r-project.org"})

    _FIELD = re.compile(
        r"^(Depends|Imports|Suggests|LinkingTo):\s*(.*?)(?=^\S+:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    _ENTRY = re.compile(r"([A-Za-z][A-Za-z0-9._]*)\s*(?:\(([^)]*)\))?")

    def normalize_name(self, name: str) -> str:
        """Folded to lower case, although CRAN itself is case-sensitive.

        `Matrix` and `matrix` are genuinely two different names there, so this
        loses a distinction. It is the right trade: a pair of CRAN packages
        differing only in case is close to unknown, while swapping the case of
        a well-known name is a standard typosquat, and folding is what lets the
        similarity check see one. Every other adapter folds for the same
        reason.
        """
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        for field_name, body in self._FIELD.findall(content.text):
            scope = Scope.DEV if field_name == "Suggests" else Scope.RUNTIME
            for chunk in body.split(","):
                match = self._ENTRY.search(chunk.strip())
                if not match or match.group(1) == "R":
                    continue
                declared.append(
                    DeclaredDependency(
                        name=match.group(1),
                        spec=(match.group(2) or "*").strip(),
                        scope=scope,
                        field_name=field_name,
                    )
                )
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )
        entries: list[LockEntry] = []
        for name, meta in (data.get("Packages") or {}).items():
            if not isinstance(meta, dict):
                continue
            requirements = meta.get("Requirements")
            entries.append(
                LockEntry(
                    name=str(meta.get("Package") or name),
                    version=str(meta.get("Version", "")),
                    integrity=BaseEcosystem._s(meta.get("Hash")),
                    resolved_from=BaseEcosystem._s(meta.get("Repository")),
                    dependencies=tuple(sorted(str(r) for r in requirements))
                    if isinstance(requirements, list)
                    else (),
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Conan (C and C++)
# ---------------------------------------------------------------------------


class ConanEcosystem(BaseEcosystem):
    """Conan, via `conanfile.txt`, `conanfile.py` and `conan.lock`.

    `conanfile.py` is Python that Conan imports, which makes it an install hook
    in the sense this project means: arbitrary code that runs during a build.
    It is registered as one, and read as text like every other manifest.
    """

    id = "conan"
    purl_type = "conan"
    manifest_globs: tuple[str, ...] = ("**/conanfile.txt", "**/conanfile.py")
    lockfile_globs: tuple[str, ...] = ("**/conan.lock",)
    registry_hosts: frozenset[str] = frozenset({"center.conan.io", "conan.io"})

    _REFERENCE = re.compile(r"([A-Za-z0-9_][A-Za-z0-9_.+-]*)/([0-9][A-Za-z0-9_.+-]*)")
    _SECTION = re.compile(r"^\[(requires|build_requires|tool_requires|test_requires)\]", re.M)
    _PY_REQUIRE = re.compile(r'(?:self\.requires|self\.build_requires|requires)\s*\(?\s*"([^"]+)"')

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        hooks: list[Hook] = []

        if content.basename == "conanfile.py":
            # Imported by Conan during a build, so it runs on every machine
            # that builds -- the same standing `setup.py` has.
            hooks.append(
                Hook(
                    kind="build",
                    path=content.path,
                    name="conanfile.py",
                    command="conan install",
                    ecosystem=self.id,
                )
            )
            for reference in self._PY_REQUIRE.findall(content.text):
                match = self._REFERENCE.match(reference)
                if match:
                    declared.append(
                        DeclaredDependency(
                            name=match.group(1), spec=match.group(2), field_name="requires"
                        )
                    )
        else:
            section: str | None = None
            for raw in content.text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                header = self._SECTION.match(line)
                if header:
                    section = header.group(1)
                    continue
                if line.startswith("["):
                    section = None
                    continue
                if section is None:
                    continue
                match = self._REFERENCE.match(line)
                if match:
                    declared.append(
                        DeclaredDependency(
                            name=match.group(1),
                            spec=match.group(2),
                            scope=Scope.RUNTIME if section == "requires" else Scope.BUILD,
                            field_name=section,
                        )
                    )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )

        # Conan 2 lists references under `requires`; Conan 1 keyed them by node
        # id under `graph_lock.nodes`. Both are in the wild.
        references: list[str] = []
        for key in ("requires", "build_requires", "python_requires"):
            section = data.get(key)
            if isinstance(section, list):
                references.extend(str(r) for r in section)
        nodes = (data.get("graph_lock") or {}).get("nodes")
        if isinstance(nodes, dict):
            references.extend(
                str(node["ref"])
                for node in nodes.values()
                if isinstance(node, dict) and node.get("ref")
            )

        entries: list[LockEntry] = []
        seen: set[tuple[str, str]] = set()
        for reference in references:
            match = self._REFERENCE.match(reference)
            if not match:
                continue
            coordinate = (match.group(1), match.group(2))
            if coordinate in seen:
                continue
            seen.add(coordinate)
            entries.append(LockEntry(name=coordinate[0], version=coordinate[1]))
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Conda
# ---------------------------------------------------------------------------


class CondaEcosystem(BaseEcosystem):
    """Conda, via `environment.yml` and `conda-lock.yml`.

    An environment file mixes conda packages with a nested `pip:` list, and the
    pip entries are PyPI packages rather than conda ones. They are declared as
    PyPI -- reporting one under a conda purl would match no advisory and name
    nothing a user could act on, and leaving them out meant nothing read them at
    all, since no PyPI glob matches `environment.yml`. OSV publishes no conda
    feed, so for an environment file those entries are the only dependencies
    that can be matched against an advisory at all.
    """

    id = "conda"
    purl_type = "conda"
    manifest_globs: tuple[str, ...] = ("**/environment.yml", "**/environment.yaml")
    lockfile_globs: tuple[str, ...] = ("**/conda-lock.yml", "**/conda-lock.yaml")
    registry_hosts: frozenset[str] = frozenset(
        {"anaconda.org", "conda.anaconda.org", "repo.anaconda.com"}
    )

    _SPEC = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*(?:[=<>!~]+\s*([^\s#]+))?")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        in_dependencies = False
        in_pip = False
        for raw in content.text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if not line[0].isspace():
                in_dependencies = line.strip().startswith("dependencies:")
                in_pip = False
                continue
            if not in_dependencies:
                continue
            stripped = line.strip()
            if stripped.startswith("- pip:"):
                in_pip = True
                continue
            # A nested list stays under `pip:` until the indentation returns.
            if in_pip and not line.startswith("    "):
                in_pip = False
            if not stripped.startswith("- "):
                continue
            match = self._SPEC.match(stripped[2:].strip().strip("'\""))
            if match and match.group(1) not in ("pip", "python"):
                declared.append(
                    DeclaredDependency(
                        name=match.group(1),
                        spec=match.group(2) or "*",
                        field_name="pip" if in_pip else "dependencies",
                        ecosystem="pypi" if in_pip else None,
                    )
                )
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        from cordon_scanner.core.config import RestrictedYamlParser

        try:
            data = RestrictedYamlParser._load_yaml_subset(content.text, source=content.path)
        except Exception as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid YAML: {exc}"
            )
        packages = data.get("package")
        if not isinstance(packages, list):
            return LockGraph(path=content.path, ecosystem=self.id)

        entries: list[LockEntry] = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = BaseEcosystem._s(package.get("name"))
            if not name or str(package.get("manager", "conda")).lower() == "pip":
                continue
            hashes = package.get("hash")
            digest = None
            if isinstance(hashes, dict):
                digest = BaseEcosystem._s(hashes.get("sha256"))
                if digest:
                    digest = f"sha256:{digest}"
            entries.append(
                LockEntry(
                    name=name,
                    version=str(package.get("version", "")),
                    integrity=digest,
                    resolved_from=BaseEcosystem._s(package.get("url")),
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


# ---------------------------------------------------------------------------
# Bazel
# ---------------------------------------------------------------------------


class BazelEcosystem(BaseEcosystem):
    """Bazel modules, via `MODULE.bazel` and `MODULE.bazel.lock`.

    Only bzlmod is read. A legacy `WORKSPACE` is Starlark whose dependencies are
    whatever its macros expand to, and a regex over it reports a fraction of the
    truth as though it were all of it -- which is the failure this project is
    organised against. A `WORKSPACE` with no `MODULE.bazel` beside it therefore
    contributes nothing here rather than something misleading.
    """

    id = "bazel"
    purl_type = "bazel"
    manifest_globs: tuple[str, ...] = ("**/MODULE.bazel",)
    lockfile_globs: tuple[str, ...] = ("**/MODULE.bazel.lock",)
    registry_hosts: frozenset[str] = frozenset({"bcr.bazel.build", "registry.bazel.build"})

    _DEP = re.compile(
        r'bazel_dep\s*\(\s*name\s*=\s*"([^"]+)"\s*,\s*version\s*=\s*"([^"]*)"([^)]*)\)',
        re.DOTALL,
    )
    _DEV = re.compile(r"dev_dependency\s*=\s*True")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        declared = [
            DeclaredDependency(
                name=name,
                spec=version or "*",
                scope=Scope.DEV if self._DEV.search(tail) else Scope.RUNTIME,
                field_name="bazel_dep",
            )
            for name, version, tail in self._DEP.findall(content.text)
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
        seen: set[tuple[str, str]] = set()
        # Keys are `@@name~version` or `name@version` depending on the Bazel
        # release that wrote the file.
        for key in data.get("moduleDepGraph") or data.get("selectedYankedVersions") or {}:
            text = str(key).lstrip("@")
            name, separator, version = text.rpartition("~")
            if not separator:
                name, separator, version = text.rpartition("@")
            if not separator or not name:
                continue
            if (name, version) in seen:
                continue
            seen.add((name, version))
            entries.append(LockEntry(name=name, version=version))
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


__all__ = [
    "BazelEcosystem",
    "CargoEcosystem",
    "CocoaPodsEcosystem",
    "ComposerEcosystem",
    "ConanEcosystem",
    "CondaEcosystem",
    "CranEcosystem",
    "GoEcosystem",
    "GradleEcosystem",
    "HexEcosystem",
    "MavenEcosystem",
    "NuGetEcosystem",
    "PubEcosystem",
    "RubyGemsEcosystem",
    "SwiftEcosystem",
]
