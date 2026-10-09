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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.core.safexml import SafeXml, SafeXmlError
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.core.content import FileContent


@dataclass
class Statement:
    """One statement of a build script, with the block that follows it, if any."""

    text: str
    line: int
    closure: list[Statement] | None = None

    @property
    def head(self) -> str:
        match = re.match(r"[A-Za-z_][\w.]*", self.text)
        return match.group(0) if match else ""


class GradleScript:
    """A Groovy or Kotlin build script split into statements and blocks.

    Strings (single, double, triple-quoted, with `${...}` templates) and comments are respected,
    so a brace inside a string or a comment never opens a block. Nothing is evaluated."""

    MAX_STATEMENTS: ClassVar[int] = 50_000
    MAX_DEPTH: ClassVar[int] = 64

    def __init__(self, text: str) -> None:
        self.text = GradleScript.without_comments(text)
        self.position = 0
        self.line = 1
        self.count = 0

    @staticmethod
    def without_comments(text: str) -> str:
        """Comments blanked (newlines kept, so line numbers hold); strings untouched."""
        out: list[str] = []
        index, length = 0, len(text)
        while index < length:
            character = text[index]
            if text.startswith(('"""', "'''"), index):
                quote = text[index : index + 3]
                end = text.find(quote, index + 3)
                end = length if end < 0 else end + 3
                out.append(text[index:end])
                index = end
            elif character in "\"'":
                end = index + 1
                while end < length and text[end] != character and text[end] != "\n":
                    end += 2 if text[end] == "\\" else 1
                end = min(end + 1, length)
                out.append(text[index:end])
                index = end
            elif text.startswith("//", index):
                end = text.find("\n", index)
                end = length if end < 0 else end
                out.append(" " * (end - index))
                index = end
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                end = length if end < 0 else end + 2
                out.append("".join(c if c == "\n" else " " for c in text[index:end]))
                index = end
            else:
                out.append(character)
                index += 1
        return "".join(out)

    def statements(self) -> list[Statement]:
        """The script's statements, or `ValueError` naming the line where its structure breaks:
        a script cut short or damaged is reported, never read as one that declares nothing."""
        if "\x00" in self.text:
            raise ValueError("it contains NUL bytes, so it is not a build script")
        out = self._block(0)
        if self.position < len(self.text):
            raise ValueError(f"line {self.line}: a closing brace with no block open")
        return out

    def _block(self, depth: int) -> list[Statement]:
        out: list[Statement] = []
        text, length = self.text, len(self.text)
        buffer: list[str] = []
        start_line = self.line
        parens = 0
        while self.position < length:
            character = text[self.position]
            if text.startswith(('"""', "'''"), self.position):
                quote = text[self.position : self.position + 3]
                end = text.find(quote, self.position + 3)
                if end < 0:
                    raise ValueError(f"line {self.line}: a string is never closed")
                end += 3
                chunk = text[self.position : end]
                self.line += chunk.count("\n")
                buffer.append(chunk)
                self.position = end
                continue
            if character in "\"'":
                end = self.position + 1
                while end < length and text[end] != character and text[end] != "\n":
                    end += 2 if text[end] == "\\" else 1
                if end >= length or text[end] != character:
                    raise ValueError(f"line {self.line}: a string is never closed")
                end += 1
                buffer.append(text[self.position : end])
                self.position = end
                continue
            if character == "(":
                parens += 1
            elif character == ")":
                parens = max(0, parens - 1)
            if character == "{" and parens == 0:
                self.position += 1
                statement = Statement("".join(buffer).strip(), start_line)
                if depth >= self.MAX_DEPTH:
                    raise ValueError(f"blocks nested deeper than {self.MAX_DEPTH}")
                statement.closure = self._block(depth + 1)
                self._emit(out, statement)
                buffer, start_line = [], self.line
                continue
            if character == "}" and parens == 0:
                if depth == 0:
                    # Left for `statements` to report: the top level has no block to close.
                    self._emit(out, Statement("".join(buffer).strip(), start_line))
                    return out
                self.position += 1
                self._emit(out, Statement("".join(buffer).strip(), start_line))
                return out
            if character in "\n;" and parens == 0:
                self._emit(out, Statement("".join(buffer).strip(), start_line))
                buffer = []
                if character == "\n":
                    self.line += 1
                self.position += 1
                start_line = self.line
                continue
            if character == "\n":
                self.line += 1
            buffer.append(character)
            self.position += 1
        if depth > 0:
            raise ValueError(f"line {start_line}: a block is never closed")
        if parens:
            raise ValueError(f"line {start_line}: a parenthesis is never closed")
        self._emit(out, Statement("".join(buffer).strip(), start_line))
        return out

    def _emit(self, out: list[Statement], statement: Statement) -> None:
        if not statement.text and statement.closure is None:
            return
        self.count += 1
        if self.count > self.MAX_STATEMENTS:
            raise ValueError(f"more than {self.MAX_STATEMENTS} statements")
        out.append(statement)


class GradleValues:
    """Literal values a script names: `val x = "..."`, `def x = '...'`, `ext.x = '...'`,
    `ext { x = '...' }`, `extra["x"] = "..."`, and `gradle.properties` beside the build."""

    ASSIGNMENT: ClassVar[re.Pattern[str]] = re.compile(
        r"""^(?:(?:val|var|def|final)\s+)?(?:ext\.|extra\[\s*["'])?([A-Za-z_][\w.]{0,100})(?:["']\s*\])?"""
        r"""\s*(?::\s*\w+)?\s*=\s*(["'])([^"'\n]{0,256})\2\s*$"""
    )
    BY_EXTRA: ClassVar[re.Pattern[str]] = re.compile(
        r"""^val\s+([A-Za-z_]\w{0,100})\s+by\s+extra\(\s*(["'])([^"'\n]{0,256})\2\s*\)$"""
    )
    TEMPLATE: ClassVar[re.Pattern[str]] = re.compile(r"\$\{?\s*([A-Za-z_][\w.]{0,100})\s*\}?")

    @staticmethod
    def collect(
        statements: list[Statement],
        into: dict[str, str],
        *,
        extra_only: bool = False,
        inside: bool = False,
    ) -> None:
        """Literal values the script assigns. With `extra_only`, only extra properties
        (`ext { }`, `ext.x =`, `extra["x"] =`, `by extra(...)`): what a parent project's script
        makes visible to its subprojects, where its local `def` variables are not."""
        for statement in statements:
            text = statement.text
            is_extra = (
                inside
                or text.startswith(("ext.", "extra[", "project.ext.", "rootProject.ext."))
                or " by extra(" in text
            )
            if not extra_only or is_extra:
                for pattern in (GradleValues.ASSIGNMENT, GradleValues.BY_EXTRA):
                    found = pattern.match(text)
                    if found:
                        into.setdefault(
                            found.group(1).removeprefix("project.").removeprefix("rootProject."),
                            found.group(3),
                        )
            if statement.closure is not None and statement.head in (
                "ext",
                "extra",
                "allprojects",
                "subprojects",
                "buildscript",
            ):
                GradleValues.collect(
                    statement.closure,
                    into,
                    extra_only=extra_only,
                    inside=inside or statement.head in ("ext", "extra"),
                )

    @staticmethod
    def properties(text: str) -> dict[str, str]:
        values: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "!")):
                continue
            key, separator, value = line.partition("=")
            if not separator:
                key, separator, value = line.partition(":")
            if separator and key.strip():
                values[key.strip()] = value.strip()
        return values

    @staticmethod
    def interpolate(value: str, values: Mapping[str, str]) -> tuple[str, bool]:
        """`value` with `$x` and `${x}` filled in, and whether every one could be."""
        complete = True

        def fill(match: re.Match[str]) -> str:
            nonlocal complete
            name = match.group(1)
            for candidate in (name, name.removeprefix("project.").removeprefix("rootProject.")):
                if candidate in values:
                    return values[candidate]
            complete = False
            return match.group(0)

        return GradleValues.TEMPLATE.sub(fill, value), complete


class GradleCatalog:
    """`gradle/libs.versions.toml`: what `libs.<alias>`, `libs.bundles.<name>` and
    `libs.plugins.<alias>` refer to. Aliases are matched the way Gradle generates accessors:
    `-`, `_` and `.` all separate, so `jackson-databind` is `libs.jackson.databind`."""

    def __init__(self, data: dict[str, Any]) -> None:
        raw_versions = data.get("versions")
        versions = raw_versions if isinstance(raw_versions, dict) else {}
        self.versions = {str(k): self._version(v) for k, v in versions.items()}
        self.libraries: dict[str, tuple[str, str]] = {}
        raw_libraries = data.get("libraries")
        for alias, entry in (raw_libraries if isinstance(raw_libraries, dict) else {}).items():
            coordinate = self._coordinate(entry)
            if coordinate[0]:
                self.libraries[self.key(str(alias))] = coordinate
        self.bundles: dict[str, list[str]] = {}
        raw_bundles = data.get("bundles")
        for name, members in (raw_bundles if isinstance(raw_bundles, dict) else {}).items():
            if isinstance(members, list):
                self.bundles[self.key(str(name))] = [
                    self.key(str(m)) for m in members if isinstance(m, str)
                ]
        self.plugins: dict[str, tuple[str, str]] = {}
        raw_plugins = data.get("plugins")
        for alias, entry in (raw_plugins if isinstance(raw_plugins, dict) else {}).items():
            if isinstance(entry, str):
                plugin_id, _, version = entry.partition(":")
                self.plugins[self.key(str(alias))] = (plugin_id, version)
            elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
                self.plugins[self.key(str(alias))] = (
                    str(entry["id"]),
                    self._ref_or_version(entry.get("version")),
                )

    @staticmethod
    def key(alias: str) -> str:
        return re.sub(r"[-_.]", ".", alias).lower()

    def _version(self, value: object) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("strictly", "require", "prefer"):
                if isinstance(value.get(key), str):
                    return str(value[key])
        return ""

    def _ref_or_version(self, version: object) -> str:
        if isinstance(version, str):
            return version
        if isinstance(version, dict):
            ref = version.get("ref")
            if isinstance(ref, str):
                return self.versions.get(ref, "")
            return self._version(version)
        return ""

    def _coordinate(self, entry: object) -> tuple[str, str]:
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) >= 2:
                return (f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else "")
            return ("", "")
        if not isinstance(entry, dict):
            return ("", "")
        module = entry.get("module")
        if isinstance(module, str) and ":" in module:
            name = module
        elif isinstance(entry.get("group"), str) and isinstance(entry.get("name"), str):
            name = f"{entry['group']}:{entry['name']}"
        else:
            return ("", "")
        return (name, self._ref_or_version(entry.get("version")))

    @staticmethod
    def load(text: str) -> GradleCatalog | None:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return None
        return GradleCatalog(data)


@dataclass
class GradleBuild:
    """What one build script declares, read statically."""

    dependencies: list[DeclaredDependency] = field(default_factory=list)
    constraints: dict[str, str] = field(default_factory=dict)
    forced: dict[str, str] = field(default_factory=dict)
    substituted: set[str] = field(default_factory=set)
    """Modules a substitution replaces: requested, never fetched, so not in the inventory. The
    module substituted in records which one it replaced."""
    """`resolutionStrategy.force` versions: unlike a constraint, they win over a declared one."""
    sources: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    included_builds: list[str] = field(default_factory=list)
    group: str | None = None
    version: str | None = None


class GradleReader:
    """Reads the declarations out of one script's statements."""

    STRING: ClassVar[re.Pattern[str]] = re.compile(r"""(["'])((?:(?!\1)[^\n\\]|\\.){0,512})\1""")
    MAP_ENTRY: ClassVar[re.Pattern[str]] = re.compile(
        r"""\b(group|name|version|classifier|ext|module)\s*[:=]\s*(["'])([^"'\n]{0,256})\2"""
    )
    LIBS: ClassVar[re.Pattern[str]] = re.compile(r"^libs\.([\w.]{1,200}?)(?:\.get\(\))?$")
    PROJECT: ClassVar[re.Pattern[str]] = re.compile(
        r"""^project\(\s*(?:path\s*[:=]\s*)?(["'])([^"']{0,200})\1"""
    )
    WRAPPERS: ClassVar[tuple[str, ...]] = ("platform", "enforcedPlatform", "testFixtures")
    SKIPPED: ClassVar[tuple[str, ...]] = (
        "files",
        "fileTree",
        "gradleApi",
        "localGroovy",
        "gradleTestKit",
    )

    #: Configuration -> scope. A variant prefix (`debugImplementation`) is read through to the
    #: configuration it extends and kept as a condition.
    SCOPES: ClassVar[dict[str, Scope]] = {
        "implementation": Scope.RUNTIME,
        "api": Scope.RUNTIME,
        "compile": Scope.RUNTIME,
        "runtime": Scope.RUNTIME,
        "runtimeOnly": Scope.RUNTIME,
        "compileOnly": Scope.BUILD,
        "compileOnlyApi": Scope.BUILD,
        "providedCompile": Scope.BUILD,
        "providedRuntime": Scope.BUILD,
        "annotationProcessor": Scope.BUILD,
        "kapt": Scope.BUILD,
        "ksp": Scope.BUILD,
        "developmentOnly": Scope.DEV,
        "classpath": Scope.TOOL,
    }
    TEST_PREFIXES: ClassVar[tuple[str, ...]] = (
        "test",
        "androidTest",
        "integrationTest",
        "functionalTest",
    )
    VARIANTS: ClassVar[re.Pattern[str]] = re.compile(
        r"^([a-z][A-Za-z0-9]*?)(Implementation|Api|CompileOnly|RuntimeOnly|AnnotationProcessor)$"
    )

    def __init__(
        self,
        path: str,
        catalog: GradleCatalog | None,
        values: dict[str, str],
        kotlin: bool,
        root: str = "",
    ) -> None:
        self.path = path
        self.catalog = catalog
        self.values = values
        self.kotlin = kotlin
        self.root = root
        """The build's root directory (where its settings script is), for `project(...)` paths."""
        self.build = GradleBuild()

    # -- scopes ---------------------------------------------------------------------------------

    def scope_of(
        self, configuration: str, *, buildscript: bool
    ) -> tuple[Scope, tuple[str, ...]] | None:
        """The scope a configuration's dependencies have, and any condition. None when the name
        is not a configuration (a call inside `dependencies {}` that declares nothing)."""
        if buildscript or configuration == "classpath":
            return Scope.TOOL, ()
        if configuration in self.SCOPES:
            return self.SCOPES[configuration], ()
        if configuration.startswith(self.TEST_PREFIXES) and configuration[0].islower():
            return Scope.TEST, ()
        if configuration.endswith("Plugins") or configuration in (
            "detekt",
            "ktlint",
            "checkstyle",
            "pmd",
            "spotbugs",
            "jacocoAgent",
            "lintChecks",
        ):
            return Scope.TOOL, ()
        variant = self.VARIANTS.match(configuration)
        if variant:
            base = variant.group(2)[0].lower() + variant.group(2)[1:]
            return self.SCOPES.get(base, Scope.RUNTIME), (f"variant {variant.group(1)}",)
        return None

    # -- statements -----------------------------------------------------------------------------

    def read(self, statements: list[Statement], context: tuple[str, ...] = ()) -> None:
        for statement in statements:
            head = statement.head
            if statement.closure is None:
                self._top_level(statement, context)
                continue
            if head == "dependencies":
                self._dependencies(statement.closure, context)
            elif head == "plugins":
                self._plugins(statement.closure, context)
            elif head in ("repositories",):
                self._repositories(statement.closure)
            elif head.startswith(
                ("configurations", "resolutionStrategy", "dependencySubstitution")
            ):
                self._resolution(statement.closure, context)
            elif head in (
                "buildscript",
                "allprojects",
                "subprojects",
                "pluginManagement",
                "dependencyResolutionManagement",
                "android",
                "kotlin",
                "java",
                "sourceSets",
            ) or head.startswith(("project", "configure")):
                self.read(statement.closure, (*context, head))
            else:
                self._top_level(statement, context)

    def _top_level(self, statement: Statement, context: tuple[str, ...]) -> None:
        text = statement.text
        for value in re.findall(r"""^include(?:\s*\(|\s+)(.*?)\)?$""", text):
            self.build.includes.extend(
                s.group(2).lstrip(":").replace(":", "/") for s in self.STRING.finditer(value)
            )
        found = re.match(r"""^includeBuild\s*\(?\s*(["'])([^"']{1,256})\1""", text)
        if found:
            self.build.included_builds.append(found.group(2))
        for key in ("group", "version"):
            found = re.match(rf"""^(?:project\.)?{key}\s*=\s*(["'])([^"'\n]{{1,128}})\1""", text)
            if found and not context:
                setattr(self.build, key, found.group(2))

    def _repositories(self, statements: list[Statement]) -> None:
        for statement in statements:
            head = statement.head
            if head in ("mavenCentral", "google", "gradlePluginPortal", "mavenLocal", "jcenter"):
                self.build.sources.append(f"repository {head}()")
                continue
            if head in ("maven", "ivy") and statement.closure is not None:
                for inner in statement.closure:
                    found = re.search(
                        r"""\burl\s*(?:=|\s)\s*(?:uri\(\s*)?(["'])([^"'\n]{1,512})\1""", inner.text
                    )
                    if found:
                        self.build.sources.append(f"repository {head}: {found.group(2)}")
                continue
            found = re.match(
                r"""^maven\s*\(\s*(?:url\s*=\s*)?(?:uri\(\s*)?(["'])([^"'\n]{1,512})\1""",
                statement.text,
            )
            if found:
                self.build.sources.append(f"repository maven: {found.group(2)}")

    def _plugins(self, statements: list[Statement], context: tuple[str, ...]) -> None:
        for statement in statements:
            text = statement.text
            plugin_id, version = "", ""
            found = re.match(r"""^id\s*\(?\s*(["'])([\w.\-]{1,200})\1\s*\)?(.*)$""", text)
            if found:
                plugin_id = found.group(2)
                rest = found.group(3)
                version_found = re.search(r"""\bversion\s*\(?\s*(["'])([^"'\n]{1,128})\1""", rest)
                version = version_found.group(2) if version_found else ""
            found_kotlin = re.match(r"""^kotlin\s*\(\s*(["'])([\w.\-]{1,100})\1\s*\)(.*)$""", text)
            if found_kotlin:
                plugin_id = f"org.jetbrains.kotlin.{found_kotlin.group(2)}"
                version_found = re.search(
                    r"""\bversion\s*\(?\s*(["'])([^"'\n]{1,128})\1""", found_kotlin.group(3)
                )
                version = version_found.group(2) if version_found else ""
            found_alias = re.match(r"""^alias\s*\(\s*libs\.plugins\.([\w.]{1,200})\s*\)""", text)
            if found_alias and self.catalog is not None:
                plugin_id, version = self.catalog.plugins.get(
                    GradleCatalog.key(found_alias.group(1)), ("", "")
                )
            if not plugin_id or "." not in plugin_id:
                # `java`, `application`, `java-library`: core plugins, part of Gradle itself.
                continue
            version, complete = GradleValues.interpolate(version, self.values)
            self.build.dependencies.append(
                DeclaredDependency(
                    name=f"{plugin_id}:{plugin_id}.gradle.plugin",
                    spec=version if version and complete else "*",
                    scope=Scope.TOOL,
                    field_name="plugins",
                    note=None
                    if version and complete
                    else "a plugin version the build does not state literally",
                )
            )

    def _dependencies(self, statements: list[Statement], context: tuple[str, ...]) -> None:
        buildscript = "buildscript" in context
        conditions = tuple(
            f"applied to {c}" for c in context if c in ("allprojects", "subprojects")
        )
        for statement in statements:
            if statement.head == "constraints" and statement.closure is not None:
                for constraint in statement.closure:
                    for declared in self._declarations(
                        constraint, buildscript=buildscript, conditions=()
                    ):
                        if declared.spec and declared.spec != "*":
                            self.build.constraints[declared.name] = declared.spec
                continue
            self.build.dependencies.extend(
                self._declarations(statement, buildscript=buildscript, conditions=conditions)
            )

    def _declarations(
        self, statement: Statement, *, buildscript: bool, conditions: tuple[str, ...]
    ) -> Iterator[DeclaredDependency]:
        text = statement.text
        found = re.match(r"^([A-Za-z_]\w*)\s*(\(|\s)(.*)$", text, re.DOTALL)
        configuration, argument = "", ""
        if found:
            configuration, argument = found.group(1), (found.group(2) + found.group(3)).strip()
        add = re.match(r"""^add\s*\(\s*(["'])(\w+)\1\s*,\s*(.*)\)$""", text, re.DOTALL)
        if add:
            configuration, argument = add.group(2), add.group(3).strip()
        if not configuration:
            return
        scoped = self.scope_of(configuration, buildscript=buildscript)
        if scoped is None:
            return
        scope, extra = scoped
        if argument.startswith("(") and argument.endswith(")"):
            argument = argument[1:-1].strip()
        exclusions, strict, capabilities = self._closure(statement.closure)
        for name, spec, platform, note, local in self._coordinates(argument):
            if local is not None:
                # Another project of this build: its source, read here, not a download.
                yield DeclaredDependency(
                    name=name,
                    spec=f"path:{self.project_path(local)}",
                    scope=scope,
                    field_name=configuration,
                    platform=(*conditions, *extra, *platform),
                )
                continue
            yield DeclaredDependency(
                name=name,
                spec=strict or spec or "*",
                scope=scope,
                field_name=configuration,
                platform=(*conditions, *extra, *platform, *capabilities),
                exclusions=exclusions,
                note=note,
            )

    SUBSTITUTE: ClassVar[re.Pattern[str]] = re.compile(
        r"""substitute\s*\(?\s*(module|project)\s*\(\s*(["'])([^"'\n]{1,200})\2\s*\)\s*\)?"""
        r"""\s*\.?\s*(?:using|with)\s*\(?\s*(module|project)\s*\(\s*(["'])([^"'\n]{1,200})\5"""
    )
    FORCE: ClassVar[re.Pattern[str]] = re.compile(r"""^force\s*\(?\s*(.*?)\)?$""", re.DOTALL)

    @staticmethod
    def _flatten(statements: list[Statement] | None) -> Iterator[Statement]:
        for statement in statements or ():
            yield statement
            yield from GradleReader._flatten(statement.closure)

    def _resolution(self, statements: list[Statement] | None, context: tuple[str, ...]) -> None:
        """`configurations { resolutionStrategy { ... } }`: rules that change what resolves.

        A substitution replaces one module with another everywhere it is requested, so what is
        fetched is the module substituted in -- inventoried here, with what it replaces in its
        note. `force` pins a version, as a constraint does."""
        buildscript = "buildscript" in context
        scope, extra = self.scope_of("implementation", buildscript=buildscript) or (
            Scope.RUNTIME,
            (),
        )
        for statement in GradleReader._flatten(statements):
            for match in self.SUBSTITUTE.finditer(statement.text):
                kind, original, target_kind, target = (
                    match.group(1),
                    match.group(3),
                    match.group(4),
                    match.group(6),
                )
                if kind == "module":
                    # `group:name`, without a version a substitution matches every one of.
                    self.build.substituted.add(":".join(original.split(":")[:2]))
                note = f"substituted for {original} by a resolution rule"
                if target_kind == "project":
                    path = target.lstrip(":").replace(":", "/")
                    self.build.dependencies.append(
                        DeclaredDependency(
                            name=path.rpartition("/")[2] or path or ".",
                            spec=f"path:{self.project_path(path or '.')}",
                            scope=scope,
                            field_name="dependencySubstitution",
                            platform=extra,
                            note=note,
                        )
                    )
                    continue
                for name, spec, platform, coordinate_note, _local in self._coordinates(
                    f'"{target}"'
                ):
                    self.build.dependencies.append(
                        DeclaredDependency(
                            name=name,
                            spec=spec or "*",
                            scope=scope,
                            field_name="dependencySubstitution",
                            platform=(*extra, *platform),
                            note=note if spec else f"{note}; {coordinate_note}",
                        )
                    )
            forced = self.FORCE.match(statement.text) if statement.head == "force" else None
            if forced:
                for literal in self.STRING.finditer(forced.group(1)):
                    for name, spec, _platform, _note, _local in self._coordinates(literal.group(0)):
                        if spec:
                            self.build.forced[name] = spec

    def project_path(self, project: str) -> str:
        """A `project(":a:b")` path, relative to this script's directory."""
        import posixpath

        target = posixpath.join(self.root, project) if self.root else project
        here = self.path.rpartition("/")[0] or "."
        return posixpath.relpath(target or ".", here)

    def _closure(
        self, closure: list[Statement] | None
    ) -> tuple[tuple[str, ...], str, tuple[str, ...]]:
        exclusions: list[str] = []
        strict = ""
        capabilities: list[str] = []
        for inner in closure or ():
            if inner.head == "capabilities" and inner.closure is not None:
                # `requireCapability("g:n")` selects the variant of the module that provides it:
                # a different artefact from the default one, recorded as a constraint on it.
                for required in inner.closure:
                    capabilities.extend(
                        f"capability {m.group(2)}"
                        for m in re.finditer(
                            r"""requireCapability\s*\(?\s*(["'])([^"'\n]{1,200})\1""", required.text
                        )
                    )
            if inner.head == "exclude":
                entries = {k: v for k, _, v in self.MAP_ENTRY.findall(inner.text)}
                group, module = entries.get("group", "*"), entries.get("module", "*")
                exclusions.append(f"{group}:{module}")
            if inner.head == "version" and inner.closure is not None:
                for rich in inner.closure:
                    found = re.match(
                        r"""^(strictly|require|prefer)\s*\(?\s*(["'])([^"'\n]{1,128})\2""",
                        rich.text,
                    )
                    if found and not strict:
                        strict = found.group(3)
        return tuple(exclusions), strict, tuple(capabilities)

    def _coordinates(
        self, argument: str
    ) -> Iterator[tuple[str, str, tuple[str, ...], str | None, str | None]]:
        """`(name, spec, conditions, note, local project)` for each coordinate an argument names."""
        wrapped = re.match(r"^(\w+)\s*\(\s*(.*)\s*\)$", argument, re.DOTALL)
        if wrapped and wrapped.group(1) in self.WRAPPERS:
            label = "platform" if wrapped.group(1) != "testFixtures" else "test fixtures"
            for name, spec, platform, note, local in self._coordinates(wrapped.group(2).strip()):
                yield name, spec, (*platform, label), note, local
            return
        if wrapped and wrapped.group(1) in self.SKIPPED:
            return
        project = self.PROJECT.match(argument)
        if project:
            path = project.group(2).lstrip(":").replace(":", "/")
            yield (path.rpartition("/")[2] or path or ".", "*", (), None, path or ".")
            return
        kotlin = re.match(r"""^kotlin\s*\(\s*(["'])([\w.\-]{1,100})\1""", argument)
        if kotlin:
            yield (
                f"org.jetbrains.kotlin:kotlin-{kotlin.group(2)}",
                "*",
                (),
                "the version comes from the Kotlin plugin",
                None,
            )
            return
        libs = self.LIBS.match(argument.strip())
        if libs:
            yield from self._catalog(libs.group(1))
            return
        entries = {k: v for k, _, v in self.MAP_ENTRY.findall(argument)}
        if "name" in entries and ("group" in entries or self.kotlin is False):
            yield self._coordinate(
                f"{entries.get('group', '')}:{entries['name']}:{entries.get('version', '')}",
                entries.get("classifier", ""),
                entries.get("ext", ""),
            )
            return
        if "module" in entries:
            yield self._coordinate(entries["module"], "", "")
            return
        for literal in self.STRING.finditer(argument):
            value = literal.group(2)
            if value.count(":") >= 1 and not value.startswith((":", "/")):
                yield self._coordinate(value, "", "")

    def _catalog(
        self, path: str
    ) -> Iterator[tuple[str, str, tuple[str, ...], str | None, str | None]]:
        if self.catalog is None:
            yield (
                f"libs.{path}",
                "*",
                (),
                "a version catalog alias, and no catalog is in the scanned tree",
                None,
            )
            return
        key = GradleCatalog.key(path)
        if key.startswith("bundles."):
            for member in self.catalog.bundles.get(key.removeprefix("bundles."), ()):
                name, version = self.catalog.libraries.get(member, ("", ""))
                if name:
                    yield (
                        name,
                        version or "*",
                        (),
                        None
                        if version
                        else "the catalog gives it no version: a platform or constraint decides",
                        None,
                    )
            return
        name, version = self.catalog.libraries.get(key, ("", ""))
        if name:
            yield (
                name,
                version or "*",
                (),
                None
                if version
                else "the catalog gives it no version: a platform or constraint decides",
                None,
            )
        else:
            yield (f"libs.{path}", "*", (), "the catalog has no library with this alias", None)

    def _coordinate(
        self, raw: str, classifier: str, extension: str
    ) -> tuple[str, str, tuple[str, ...], str | None, str | None]:
        value, complete = GradleValues.interpolate(raw, self.values)
        if "@" in value:
            value, _, extension = value.partition("@")
        parts = value.split(":")
        group, artifact = parts[0], parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""
        if len(parts) > 3:
            classifier = parts[3]
        conditions = []
        if classifier:
            conditions.append(f"classifier {classifier}")
        if extension and extension != "jar":
            conditions.append(f"type {extension}")
        note = None
        if not complete:
            note = "the coordinate uses a value the build computes, which a static read cannot know"
            if "$" in version:
                version = ""
        elif not version:
            note = "no version is declared: a platform, a constraint or the catalog decides"
        return (f"{group}:{artifact}", version, tuple(conditions), note, None)


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
            if not line or line.startswith("#") or line.startswith("empty="):
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


__all__ = ["GradleCatalog", "GradleEcosystem", "GradleLock", "GradleScript", "GradleVerification"]
