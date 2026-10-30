"""Maven: pom.xml with its parents and properties, the dependency tree and checksum files, and the Maven wrapper."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar
from xml.sax.saxutils import escape

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

# Each `*Ecosystem` imported below from its own module (GitHub Actions, Bazel, CocoaPods, Composer,
# Conan, Conda, CRAN, Gradle, Hex, NuGet, Pub, RubyGems, Swift) is re-exported where it always lived.
from cordon_scanner.foundation.formats.safexml import Element, SafeXml, SafeXmlError
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.foundation.content import FileContent


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

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.split(":", 1)[0] if ":" in name else None

    def coordinate_separator(self) -> str | None:
        return ":"

    def is_mutable_version(self, version: str) -> bool:
        return version.upper().endswith("-SNAPSHOT")

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

    # -- the projects mcp writes for a package check (EcosystemProjects) ------------

    def pinned_project(self, pins: Sequence[tuple[str, str]]) -> dict[str, str] | None:
        """A project pinning these releases, as its own lockfile: `{path: content}`."""

        def xml(value: str) -> str:
            return escape(value, {'"': "&quot;"})

        deps = "".join(
            f"<dependency><groupId>{xml(name.split(':')[0])}</groupId>"
            f"<artifactId>{xml(name.split(':')[1])}</artifactId>"
            f"<version>{xml(version or '')}</version></dependency>"
            for name, version in pins
        )
        return {
            "pom.xml": '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<modelVersion>4.0.0</modelVersion><groupId>cordon.check</groupId>"
            "<artifactId>check</artifactId><version>1</version>"
            f"<dependencies>{deps}</dependencies></project>"
        }

    def loose_project(self, names: Sequence[str]) -> dict[str, str] | None:
        """A project naming these packages with no version: `{path: content}`."""

        def xml(value: str) -> str:
            return escape(value, {'"': "&quot;"})

        deps = "".join(
            f"<dependency><groupId>{xml(name.split(':')[0])}</groupId>"
            f"<artifactId>{xml(name.split(':')[1])}</artifactId></dependency>"
            for name in names
        )
        return {
            "pom.xml": '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<modelVersion>4.0.0</modelVersion><groupId>cordon.check</groupId>"
            "<artifactId>check</artifactId><version>1</version>"
            f"<dependencies>{deps}</dependencies></project>"
        }

    # -- the release a published archive is (EcosystemReleaseIdentity) -------------

    def release_manifest(self) -> re.Pattern[str] | None:
        """`<group>/<artifact>/pom.properties` inside a jar: the coordinates Maven resolved."""
        return MavenEcosystem.POM_PROPERTIES

    def release_identity(
        self, path: str, text: str, found: re.Match[str]
    ) -> tuple[str, str] | None:
        return MavenEcosystem.pom_identity(path, text)

    POM_PROPERTIES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|!)META-INF/maven/[^/!]+/[^/!]+/pom\.properties$"
    )

    @staticmethod
    def pom_identity(path: str, text: str) -> tuple[str, str] | None:
        """`group:artifact` and version from a jar's `pom.properties`."""
        group = re.search(r"(?m)^groupId=(\S+)", text)
        artifact = re.search(r"(?m)^artifactId=(\S+)", text)
        said = re.search(r"(?m)^version=(\S+)", text)
        if group and artifact and said:
            # A shaded jar carries the poms of what it bundles, and may not carry its
            # own: only a pom whose artifact the jar was published as names it.
            archive = path.split("!", 1)[0]
            if f"{artifact.group(1)}-{said.group(1)}" in archive:
                return f"{group.group(1)}:{artifact.group(1)}", said.group(1)
        return None


__all__ = [
    "MavenBuild",
    "MavenChecksums",
    "MavenDependency",
    "MavenEcosystem",
    "MavenPom",
    "MavenTree",
    "MavenWrapper",
]
