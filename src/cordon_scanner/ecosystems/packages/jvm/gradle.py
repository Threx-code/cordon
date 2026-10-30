"""Gradle: build scripts read, never run.

A Gradle build is a program -- Groovy or Kotlin evaluated on every build -- and the only exact
answer to "what does it depend on" is to run it. That is the one thing a scanner must not do with
code it was asked to inspect. So the scripts are read statically, the way a reviewer reads them:

```
  settings.gradle(.kts)        include(...), includeBuild(...), repositories, plugins
  build.gradle(.kts)           dependencies { ... }, constraints, platform(...), plugins { ... },
                               buildscript { dependencies { classpath ... } }, repositories
  gradle/libs.versions.toml    the version catalog every `libs.x.y` refers to
  gradle.lockfile              what Gradle resolved, per configuration (dependency locking)
  gradle/verification-metadata.xml
                               the checksum of every artefact the build fetched
```

What the scripts compute (a coordinate built in a loop, a version read from a remote file) cannot
be known without running them, and is reported unresolved with that reason; what they state
literally -- which is almost all of it in practice -- is read exactly. The lockfile, when the
project commits one, is the resolution.
"""

from __future__ import annotations

import dataclasses
import re
import tomllib
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.packages.jvm.maven import MavenEcosystem
from cordon_scanner.foundation.formats.safexml import SafeXml, SafeXmlError
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleCatalog
    from cordon_scanner.foundation.content import FileContent


class GradleLock:
    """`gradle.lockfile` (and `buildscript-gradle.lockfile`, `settings-gradle.lockfile`, and the
    pre-6.8 `gradle/dependency-locks/<configuration>.lockfile`): one line per resolved module,
    with the configurations that resolved it.

    ```
      com.google.guava:guava:33.3.1-jre=compileClasspath,runtimeClasspath
      empty=annotationProcessor
    ```

    The configurations decide the scope: on a runtime classpath it ships; only on a compile
    classpath it is compile-only (provided); only in annotation processing it is build tooling;
    only on test classpaths it is test; on a buildscript `classpath` it is the build's own tooling.
    """

    LINE: ClassVar[re.Pattern[str]] = re.compile(
        r"^([^:=\s]{1,256}):([^:=\s]{1,256}):([^:=\s]{1,128})=([\w,\-]{0,4096})$"
    )

    @staticmethod
    def scope(configurations: list[str], *, buildscript: bool) -> Scope:
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleReader

        if buildscript:
            return Scope.TOOL
        lowered = [c for c in configurations if c]
        test = [c for c in lowered if c.startswith(GradleReader.TEST_PREFIXES)]
        main = [c for c in lowered if c not in test]
        if any(c.endswith("RuntimeClasspath") or c == "runtimeClasspath" for c in main):
            return Scope.RUNTIME
        if any(c.endswith("CompileClasspath") or c == "compileClasspath" for c in main):
            return Scope.BUILD
        if main:
            return (
                Scope.BUILD
                if any("annotationprocessor" in c.lower() or c in ("kapt", "ksp") for c in main)
                else Scope.RUNTIME
            )
        return Scope.TEST if test else Scope.RUNTIME

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        name = content.basename
        legacy = "/dependency-locks/" in f"/{content.path}"
        buildscript = name.startswith(("buildscript-", "settings-")) or (
            legacy and name.startswith("classpath")
        )
        if content.text and not content.text.endswith("\n"):
            # Gradle ends every lockfile it writes with a newline. One that stops mid-line was cut
            # short, and what it no longer lists cannot be told from what it never had.
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="the file ends mid-line: it was cut short, so its entries are incomplete",
            )
        entries: list[LockEntry] = []
        unreadable = 0
        for raw in content.text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "empty=")):
                continue
            if legacy and "=" not in line:
                line = f"{line}={name.removesuffix('.lockfile')}"
            found = GradleLock.LINE.match(line)
            if not found:
                unreadable += 1
                continue
            group, artifact, version, configurations = found.groups()
            listed = [c for c in configurations.split(",") if c]
            entries.append(
                LockEntry(
                    name=f"{group}:{artifact}",
                    version=version,
                    scope=GradleLock.scope(listed, buildscript=buildscript),
                    direct=False,
                )
            )
        if unreadable and not entries:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} line(s) are not 'group:name:version=configurations'",
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            integrity_elsewhere=True,
            # `<project>/gradle/dependency-locks/<configuration>.lockfile` belongs to <project>.
            owner_levels=2 if legacy else 0,
        )


class GradleVerification:
    """`gradle/verification-metadata.xml`: Gradle dependency verification, the checksum of every
    artefact the build fetched. Read structurally (`core/safexml.py`); a companion that completes
    the resolved entries of every project of the build with the jar's recorded digest."""

    ALGORITHMS: ClassVar[tuple[str, ...]] = ("sha512", "sha256", "sha1", "md5")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            root = SafeXml.parse(content.text, source=content.path)
        except SafeXmlError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not readable verification metadata: {exc}",
            )
        if root.local != "verification-metadata":
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="not a <verification-metadata> document",
            )
        entries: list[LockEntry] = []
        for component in root.find_all("components", "component"):
            group = component.attributes.get("group", "")
            name = component.attributes.get("name", "")
            version = component.attributes.get("version", "")
            if not (group and name and version):
                continue
            stem = f"{name}-{version}"
            best: tuple[int, str] | None = None
            for artifact in component.find_all("artifact"):
                filename = artifact.attributes.get("name", "")
                extension = filename.rpartition(".")[2]
                classified = filename.startswith(f"{stem}-")
                rank = (
                    0
                    if extension == "jar" and not classified
                    else 1
                    if extension == "jar"
                    else 2
                    if extension not in ("pom", "module")
                    else 3
                )
                for algorithm in GradleVerification.ALGORITHMS:
                    digest = artifact.find(algorithm)
                    if digest is not None and digest.attributes.get("value"):
                        candidate = (rank, f"{algorithm}:{digest.attributes['value'].lower()}")
                        if best is None or candidate[0] < best[0]:
                            best = candidate
                        break
            entries.append(
                LockEntry(
                    name=f"{group}:{name}", version=version, integrity=best[1] if best else None
                )
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            companion=True,
            companion_tree=True,
            owner_levels=1,
        )


class GradleWrapper:
    """`gradle/wrapper/gradle-wrapper.properties`: the Gradle distribution `./gradlew` downloads and
    runs for every build."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleValues

        values = GradleValues.properties(content.text)
        url = values.get("distributionUrl", "").replace("\\:", ":")
        found = re.search(r"/gradle-([\w.\-]+?)-(?:bin|all)\.zip$", url)
        if not found:
            return BaseEcosystem._err(
                content,
                ecosystem,
                "no readable distributionUrl naming a gradle-<version> distribution"
                if url
                else "no distributionUrl: the wrapper names no Gradle distribution",
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=(
                DeclaredDependency(
                    name="org.gradle:gradle",
                    spec=found.group(1),
                    scope=Scope.TOOL,
                    field_name="distributionUrl",
                    source=url,
                ),
            ),
        )


class GradleEcosystem(BaseEcosystem):
    id = "gradle"

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.split(":", 1)[0] if ":" in name else None

    def coordinate_separator(self) -> str | None:
        return ":"

    def is_mutable_version(self, version: str) -> bool:
        return version.upper().endswith("-SNAPSHOT")

    purl_type = "maven"
    manifest_globs: tuple[str, ...] = (
        "**/build.gradle",
        "**/build.gradle.kts",
        "**/settings.gradle",
        "**/settings.gradle.kts",
        "**/gradle/libs.versions.toml",
        "**/gradle/wrapper/gradle-wrapper.properties",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/gradle.lockfile",
        "**/buildscript-gradle.lockfile",
        "**/settings-gradle.lockfile",
        "**/gradle/dependency-locks/*.lockfile",
        "**/gradle/verification-metadata.xml",
    )
    registry_hosts: frozenset[str] = frozenset(
        {
            "repo.maven.apache.org",
            "repo1.maven.org",
            "plugins.gradle.org",
            "jcenter.bintray.com",
            # Where Gradle itself publishes the distributions the wrapper downloads.
            "services.gradle.org",
            "downloads.gradle.org",
        }
    )
    records_integrity = False
    """`gradle.lockfile` records versions, never hashes: Gradle keeps those in
    `gradle/verification-metadata.xml`, applied to the locked entries when the build has one."""
    integrity_companion = True

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        found = {}
        for condition in platform:
            kind, _, value = condition.partition(" ")
            if kind in ("classifier", "type") and value and " " not in value:
                found[kind] = value
        return ("?" + "&".join(f"{k}={v}" for k, v in sorted(found.items()))) if found else ""

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    @staticmethod
    def _catalog_for(path: str, files: Mapping[str, FileContent]) -> GradleCatalog | None:
        """The catalog of the build this script belongs to: `gradle/libs.versions.toml` in its
        directory or the nearest one above it."""
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleCatalog

        directory = path.rpartition("/")[0]
        while True:
            candidate = (
                f"{directory}/gradle/libs.versions.toml"
                if directory
                else "gradle/libs.versions.toml"
            )
            if candidate in files:
                return GradleCatalog.load(files[candidate].text)
            if not directory:
                return None
            directory = directory.rpartition("/")[0]

    @staticmethod
    def _settings_for(
        path: str, files: Mapping[str, FileContent]
    ) -> tuple[str, FileContent | None]:
        """The build root (the nearest directory at or above the script with a settings script)
        and that settings script."""
        directory = path.rpartition("/")[0]
        while True:
            for name in ("settings.gradle.kts", "settings.gradle"):
                candidate = f"{directory}/{name}" if directory else name
                if candidate in files:
                    return directory, files[candidate]
            if not directory:
                return path.rpartition("/")[0], None
            directory = directory.rpartition("/")[0]

    @staticmethod
    def _project_name(path: str, files: Mapping[str, FileContent]) -> str:
        """`rootProject.name` for the script beside its settings, else the directory's name --
        which is what Gradle names a subproject."""
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleScript

        directory = path.rpartition("/")[0]
        root, settings = GradleEcosystem._settings_for(path, files)
        if settings is not None and root == directory:
            found = re.search(
                r"""rootProject\.name\s*=\s*(["'])([^"'\n]{1,128})\1""",
                GradleScript.without_comments(settings.text),
            )
            if found:
                return found.group(2)
        return directory.rpartition("/")[2]

    @staticmethod
    def _inherited_extras(path: str, root: str, files: Mapping[str, FileContent]) -> dict[str, str]:
        """Extra properties the parent projects' scripts define, nearest parent winning: Gradle
        looks a property up the project hierarchy, so `$kotlinVersion` set in the root's
        `ext { }` is visible in every subproject."""
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleScript, GradleValues

        directory = path.rpartition("/")[0]
        ancestors: list[str] = []
        while directory != root and directory:
            directory = directory.rpartition("/")[0]
            ancestors.append(directory)
            if len(ancestors) > 32:
                break
        values: dict[str, str] = {}
        for ancestor in reversed(ancestors):
            for name in ("build.gradle.kts", "build.gradle"):
                candidate = f"{ancestor}/{name}" if ancestor else name
                if candidate not in files or candidate == path:
                    continue
                try:
                    statements = GradleScript(files[candidate].text).statements()
                except ValueError:
                    continue
                found: dict[str, str] = {}
                GradleValues.collect(statements, found, extra_only=True)
                values.update(found)
        return values

    @staticmethod
    def _properties_for(path: str, files: Mapping[str, FileContent]) -> dict[str, str]:
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import GradleValues

        values: dict[str, str] = {}
        directory = path.rpartition("/")[0]
        chain = []
        while True:
            chain.append(f"{directory}/gradle.properties" if directory else "gradle.properties")
            if not directory:
                break
            directory = directory.rpartition("/")[0]
        for candidate in reversed(chain):
            if candidate in files:
                values.update(GradleValues.properties(files[candidate].text))
        return values

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        from cordon_scanner.ecosystems.packages.jvm.gradle_scripts import (
            GradleCatalog,
            GradleReader,
            GradleScript,
            GradleValues,
        )

        name = content.basename
        if name == "gradle-wrapper.properties":
            return GradleWrapper.parse(content, self.id)
        if name == "libs.versions.toml":
            catalog = GradleCatalog.load(content.text)
            if catalog is None:
                try:
                    tomllib.loads(content.text)
                except (tomllib.TOMLDecodeError, ValueError) as exc:
                    return BaseEcosystem._err(content, self.id, f"invalid TOML: {exc}")
                return BaseEcosystem._err(content, self.id, "not a version catalog")
            # A catalog says what is available, not what is used: an alias no build references is
            # not a dependency. Its entries are what `libs.<alias>` in the scripts resolve to.
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                shared_specs={
                    name: version for name, version in catalog.libraries.values() if version
                },
            )
        try:
            statements = GradleScript(content.text).statements()
        except ValueError as exc:
            return BaseEcosystem._err(content, self.id, f"not a readable build script: {exc}")
        values = self._properties_for(content.path, files)
        own: dict[str, str] = {}
        GradleValues.collect(statements, own)
        root, _ = self._settings_for(content.path, files)
        inherited = self._inherited_extras(content.path, root, files)
        values = {**values, **inherited, **own}
        reader = GradleReader(
            content.path,
            self._catalog_for(content.path, files),
            values,
            content.basename.endswith(".kts"),
            root,
        )
        reader.read(statements)
        build = reader.build
        # A script is a program evaluated on every build: a build hook by nature.
        hooks = (
            Hook(
                kind="build",
                path=content.path,
                name=content.basename,
                command="gradle build",
                ecosystem=self.id,
            ),
        )
        project_name = self._project_name(content.path, files) if build.group else ""
        dependencies = [
            dataclasses.replace(
                declared,
                spec=build.forced[declared.name],
                note=f"forced from {declared.spec} by a resolution rule",
            )
            if declared.name in build.forced and declared.spec != build.forced[declared.name]
            else declared
            for declared in build.dependencies
            if declared.name not in build.substituted
        ]
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=f"{build.group}:{project_name}" if build.group and project_name else None,
            version=build.version,
            dependencies=tuple(dependencies),
            hooks=hooks,
            overrides={**build.constraints, **build.forced},
            sources=tuple(dict.fromkeys(build.sources)),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "verification-metadata.xml":
            return GradleVerification.parse(content, self.id)
        return GradleLock.parse(content, self.id)

    # -- the release a published archive is (EcosystemReleaseIdentity) -------------

    def release_manifest(self) -> re.Pattern[str] | None:
        """A Gradle-built jar carries Maven's `pom.properties`."""
        return MavenEcosystem.POM_PROPERTIES

    def release_identity(
        self, path: str, text: str, found: re.Match[str]
    ) -> tuple[str, str] | None:
        return MavenEcosystem.pom_identity(path, text)

    # -- how its graph is resolved (EcosystemResolution) ---------------------------

    def bracket_ranges(self) -> bool:
        """A declared version may be a Maven range: `[1.0,2.0)`."""
        return True


__all__ = ["GradleEcosystem", "GradleLock", "GradleVerification"]
