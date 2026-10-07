"""Conan (C and C++).

```
  conanfile.txt      [requires] [tool_requires] [build_requires] [test_requires] [options]
                     [generators] [layout]
  conanfile.py       a recipe: Python Conan imports and runs. Read here through Python's syntax
                     tree, never executed: self.requires / tool_requires / build_requires /
                     test_requires / python_requires calls (with override=True, build=True,
                     and the `if` they sit under) and the class attributes of the same names
  conan.lock         Conan 2 (lock version 0.5): requires (host context), build_requires (build
                     context), python_requires, config_requires, overrides -- each a reference
                     `name/version[@user/channel]#recipe-revision%timestamp`.
                     Conan 1 (0.4): graph_lock.nodes, each with its ref, package_id, package
                     revision, context and edges
  profiles/default   settings, options, and [tool_requires] a profile injects into every build
  remotes.json       the remotes, searched in order
```

A recipe revision is the MD5 of the recipe's manifest: what ConanCenter lists per version, and what
a lock pins -- recorded as the record's integrity. A package id and package revision name a binary
built from that recipe, which is a different thing from the recipe: carried as purl qualifiers.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple

from cordon_scanner.core.datayaml import DataYaml
from cordon_scanner.core.models import Hook, Scope
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


REFERENCE = re.compile(
    r"^(?P<name>[a-z0-9_][a-z0-9_+.\-]{0,100})/(?P<version>\[[^\]]{1,200}\]|[A-Za-z0-9_+.\-]{1,100})"
    r"(?:@(?P<user>[A-Za-z0-9_+.\-]{1,100})(?:/(?P<channel>[A-Za-z0-9_+.\-]{1,100}))?)?"
    r"(?:#(?P<revision>[^%:#\s]{1,64})(?:%[0-9.]+)?)?"
    r"(?::(?P<package_id>[0-9a-fA-F]{1,64})(?:#(?P<package_revision>[0-9a-fA-F]{1,64})(?:%[0-9.]+)?)?)?$"
)
"""`name/version[@user/channel][#rrev[%time]][:package_id[#prev[%time]]]`."""


class Reference(NamedTuple):
    name: str
    version: str
    user: str | None
    channel: str | None
    revision: str | None
    package_id: str | None
    package_revision: str | None

    @staticmethod
    def parse(text: str) -> Reference | None:
        found = REFERENCE.match(text.strip())
        if not found:
            return None
        user = found.group("user")
        channel = found.group("channel")
        return Reference(
            found.group("name"),
            found.group("version"),
            None if user in (None, "_") else user,
            None if channel in (None, "_") else channel,
            found.group("revision"),
            found.group("package_id"),
            found.group("package_revision"),
        )

    def spec(self) -> str:
        """A version or a range: `[>=10 <11]` as written, without its brackets."""
        return self.version[1:-1].strip() if self.version.startswith("[") else self.version

    def conditions(self) -> tuple[str, ...]:
        """The recipe's namespace and the binary's identity, for the purl's qualifiers."""
        out = []
        for key, value in (
            ("user", self.user),
            ("channel", self.channel),
            ("package_id", self.package_id),
            ("prev", self.package_revision),
        ):
            if value:
                out.append(f"{key} {value}")
        return tuple(out)


class ConanText:
    """conanfile.txt."""

    SECTIONS: ClassVar[dict[str, Scope]] = {
        "requires": Scope.RUNTIME,
        "tool_requires": Scope.TOOL,
        "build_requires": Scope.TOOL,
        "test_requires": Scope.TEST,
    }
    KNOWN: ClassVar[frozenset[str]] = frozenset(
        {*SECTIONS, "options", "generators", "layout", "imports"}
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        section: str | None = None
        for raw in content.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            header = re.fullmatch(r"\[([a-z_]+)\]", line)
            if header:
                section = header.group(1)
                if section not in ConanText.KNOWN:
                    return BaseEcosystem._err(
                        content, ecosystem, "a section conanfile.txt does not have"
                    )
                continue
            if section in ConanText.SECTIONS:
                reference = Reference.parse(line)
                if reference is None:
                    return BaseEcosystem._err(
                        content, ecosystem, f"a [{section}] line that is not a Conan reference"
                    )
                declared.append(
                    DeclaredDependency(
                        name=reference.name,
                        spec=reference.spec(),
                        scope=ConanText.SECTIONS[section],
                        field_name=section,
                        platform=reference.conditions(),
                    )
                )
            elif section == "options":
                sources.append(f"option {line}")
            elif section is None:
                return BaseEcosystem._err(content, ecosystem, "a line outside any section")
        if not declared and not sources:
            return BaseEcosystem._err(content, ecosystem, "a conanfile.txt that requires nothing")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class ConanRecipe:
    """conanfile.py, read through its syntax tree. Nothing in it runs."""

    METHODS: ClassVar[dict[str, Scope]] = {
        "requires": Scope.RUNTIME,
        "tool_requires": Scope.TOOL,
        "build_requires": Scope.TOOL,
        "test_requires": Scope.TEST,
        "python_requires": Scope.BUILD,
    }
    MAX_BYTES: ClassVar[int] = 2_000_000

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        hook = Hook(
            kind="build",
            path=content.path,
            name="conanfile.py",
            command="conan install",
            ecosystem=ecosystem,
        )
        if len(content.text) > ConanRecipe.MAX_BYTES:
            return BaseEcosystem._err(content, ecosystem, "a recipe larger than a recipe is")
        try:
            tree = ast.parse(content.text, filename="conanfile.py")
        except (SyntaxError, ValueError, RecursionError):
            manifest = BaseEcosystem._err(content, ecosystem, "not a readable Python recipe")
            return Manifest(
                path=manifest.path,
                ecosystem=ecosystem,
                parse_error=manifest.parse_error,
                hooks=(hook,),
            )
        if any(
            isinstance(n, ast.Expr) and isinstance(n.value, (ast.Name, ast.Attribute))
            for n in ast.walk(tree)
        ):
            # A lone name as a statement does nothing, and no recipe has one: it is what a file cut
            # mid-statement (`ver` of `version = ...`) still parses as.
            manifest = BaseEcosystem._err(content, ecosystem, "a recipe statement cut short")
            return Manifest(
                path=manifest.path,
                ecosystem=ecosystem,
                parse_error=manifest.parse_error,
                hooks=(hook,),
            )
        declared: list[DeclaredDependency] = []
        overrides: dict[str, str] = {}
        sources: list[str] = []
        name = version = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for statement in node.body:
                    if (
                        not isinstance(statement, ast.Assign)
                        or len(statement.targets) != 1
                        or not isinstance(statement.targets[0], ast.Name)
                    ):
                        continue
                    target = statement.targets[0].id
                    if target in ConanRecipe.METHODS:
                        for text in ConanRecipe.strings(statement.value):
                            ConanRecipe.add(
                                declared,
                                overrides,
                                text,
                                ConanRecipe.METHODS[target],
                                target,
                                (),
                                override=False,
                            )
                    elif target == "name":
                        name = ConanRecipe.constant(statement.value)
                    elif target == "version":
                        version = ConanRecipe.constant(statement.value)
                    elif target == "default_options" and isinstance(statement.value, ast.Dict):
                        for key, value in zip(
                            statement.value.keys, statement.value.values, strict=False
                        ):
                            option, setting = ConanRecipe.constant(key), ConanRecipe.constant(value)
                            if option is not None and setting is not None:
                                sources.append(f"option {option}={setting}")
        ConanRecipe.calls(tree.body, (), declared, overrides, 0)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=name,
            version=version,
            dependencies=tuple(declared),
            hooks=(hook,),
            overrides=overrides,
            sources=tuple(sources),
        )

    @staticmethod
    def constant(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int)):
            return str(node.value)
        return None

    @staticmethod
    def strings(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [
                e.value
                for e in node.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
        return []

    @staticmethod
    def calls(
        body: list[ast.stmt],
        conditions: tuple[str, ...],
        declared: list[DeclaredDependency],
        overrides: dict[str, str],
        depth: int,
    ) -> None:
        """`self.<method>("ref", ...)` calls, with the `if` conditions they sit under."""
        if depth > 64:
            return
        for statement in body:
            if isinstance(statement, ast.If):
                test = ast.unparse(statement.test)[:200]
                ConanRecipe.calls(
                    statement.body, (*conditions, test), declared, overrides, depth + 1
                )
                ConanRecipe.calls(
                    statement.orelse, (*conditions, f"not ({test})"), declared, overrides, depth + 1
                )
                continue
            for child_body in ("body", "orelse", "finalbody", "handlers"):
                inner = getattr(statement, child_body, None)
                if (
                    isinstance(inner, list)
                    and inner
                    and isinstance(inner[0], ast.AST)
                    and not isinstance(statement, ast.If)
                ):
                    ConanRecipe.calls(
                        [s for s in inner if isinstance(s, ast.stmt)],
                        conditions,
                        declared,
                        overrides,
                        depth + 1,
                    )
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                function = call.func
                if (
                    isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "self"
                    and function.attr in ConanRecipe.METHODS
                    and call.args
                ):
                    text = ConanRecipe.constant(call.args[0])
                    if text is None:
                        continue
                    keywords = {
                        k.arg: ConanRecipe.constant(k.value) for k in call.keywords if k.arg
                    }
                    scope = ConanRecipe.METHODS[function.attr]
                    if function.attr == "requires" and keywords.get("build") == "True":
                        scope = Scope.BUILD
                    ConanRecipe.add(
                        declared,
                        overrides,
                        text,
                        scope,
                        function.attr,
                        conditions,
                        override=keywords.get("override") == "True",
                    )

    @staticmethod
    def add(
        declared: list[DeclaredDependency],
        overrides: dict[str, str],
        text: str,
        scope: Scope,
        field_name: str,
        conditions: tuple[str, ...],
        *,
        override: bool,
    ) -> None:
        reference = Reference.parse(text)
        if reference is None:
            return
        if override:
            # `override=True` does not add a dependency: it sets the version every package that
            # requires this one gets.
            overrides[reference.name] = reference.spec()
            return
        declared.append(
            DeclaredDependency(
                name=reference.name,
                spec=reference.spec(),
                scope=scope,
                field_name=field_name,
                platform=(*conditions, *reference.conditions()),
            )
        )


class ConanLock:
    """conan.lock, Conan 2 (0.5) and Conan 1 (0.4)."""

    SECTIONS: ClassVar[dict[str, Scope]] = {
        "requires": Scope.RUNTIME,
        "build_requires": Scope.BUILD,
        "python_requires": Scope.BUILD,
        "config_requires": Scope.TOOL,
    }

    @staticmethod
    def entry(
        reference: Reference, scope: Scope, dependencies: tuple[str, ...] = (), direct: bool = False
    ) -> LockEntry:
        return LockEntry(
            name=reference.name,
            version=reference.version,
            integrity=f"md5:{reference.revision.lower()}" if reference.revision else None,
            # ConanCenter has no user/channel namespaces: a recipe in one comes from a remote the
            # organisation runs.
            resolved_from=f"registry:{reference.user}/{reference.channel or '_'}"
            if reference.user
            else None,
            scope=scope,
            dependencies=dependencies,
            direct=direct,
            platform=reference.conditions(),
        )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        nodes = (
            data.get("graph_lock", {}).get("nodes")
            if isinstance(data.get("graph_lock"), dict)
            else None
        )
        if isinstance(nodes, dict):
            return ConanLock.conan1(content, ecosystem, nodes)
        if "version" not in data or not any(
            isinstance(data.get(k), list) for k in ConanLock.SECTIONS
        ):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a conan.lock with neither requires nor a graph_lock",
            )
        entries: list[LockEntry] = []
        for section, scope in ConanLock.SECTIONS.items():
            listed = data.get(section)
            for item in listed if isinstance(listed, list) else []:
                reference = Reference.parse(str(item))
                if reference is None:
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error=f"a {section} entry that is not a Conan reference",
                    )
                entries.append(ConanLock.entry(reference, scope))
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def conan1(content: FileContent, ecosystem: str, nodes: dict[str, Any]) -> LockGraph:
        """Conan 1's graph lock: nodes by id with `requires` / `build_requires` edges; node 0 is
        the consumer (the project itself)."""
        references: dict[str, Reference] = {}
        for key, node in nodes.items():
            if not isinstance(node, dict) or not node.get("ref"):
                continue
            reference = Reference.parse(str(node["ref"]))
            if reference is None:
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a node whose ref is not a Conan reference",
                )
            package_id, package_revision = node.get("package_id"), node.get("prev")
            references[key] = reference._replace(
                package_id=str(package_id)
                if isinstance(package_id, str) and re.fullmatch(r"[0-9a-f]{1,64}", package_id)
                else reference.package_id,
                package_revision=str(package_revision)
                if isinstance(package_revision, str)
                and re.fullmatch(r"[0-9a-f]{1,64}", package_revision)
                else reference.package_revision,
            )
        first = nodes.get("0")
        root: dict[str, Any] = first if isinstance(first, dict) else {}
        direct_host = {str(i) for i in root.get("requires") or []}
        direct_build = {str(i) for i in root.get("build_requires") or []}
        entries: list[LockEntry] = []
        for key, reference in references.items():
            if key == "0":
                continue
            node = nodes[key]
            children = [
                str(i) for i in (node.get("requires") or []) + (node.get("build_requires") or [])
            ]
            context = node.get("context")
            scope = (
                Scope.TOOL
                if key in direct_build
                else Scope.BUILD
                if context == "build"
                else Scope.RUNTIME
            )
            entries.append(
                ConanLock.entry(
                    reference,
                    scope,
                    tuple(references[c].name for c in children if c in references),
                    direct=key in direct_host or key in direct_build,
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class ConanProfile:
    """A profile: [settings], [options], [tool_requires], [conf], [buildenv]."""

    ASSIGNMENTS: ClassVar[frozenset[str]] = frozenset(
        {"settings", "options", "conf", "buildenv", "runenv", "env"}
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        section: str | None = None
        settings: list[str] = []
        sources: list[str] = []
        declared: list[DeclaredDependency] = []
        for raw in content.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("include(", "{%", "{{")):
                continue
            header = re.fullmatch(r"\[([a-z_]+)\]", line)
            if header:
                section = header.group(1)
                continue
            if section in ConanProfile.ASSIGNMENTS and "=" not in line:
                # Every line of these sections is `name=value`: one that is not was cut short.
                return BaseEcosystem._err(
                    content, ecosystem, f"a [{section}] line that is not name=value"
                )
            if section == "settings":
                settings.append(line.replace(" ", ""))
            elif section == "options":
                sources.append(f"option {line}")
            elif section in ("tool_requires", "build_requires"):
                # `ninja/1.11.1`, or `<pattern>: ref, ref` (`openssl/*: nasm/2.15.05`).
                pattern, listed = "", line
                if Reference.parse(line.split(",")[0]) is None and ":" in line:
                    pattern, _, listed = line.partition(":")
                for text in listed.split(","):
                    reference = Reference.parse(text)
                    if reference is None:
                        return BaseEcosystem._err(
                            content, ecosystem, f"a [{section}] line that is not a Conan reference"
                        )
                    declared.append(
                        DeclaredDependency(
                            name=reference.name,
                            spec=reference.spec(),
                            scope=Scope.TOOL,
                            field_name=f"profile {section}",
                            platform=(f"applies to {pattern.strip()}",) if pattern.strip() else (),
                        )
                    )
        if settings:
            sources.insert(0, f"profile settings {', '.join(settings)}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class ConanRemotes:
    """remotes.json: the remotes, in the order Conan searches them."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        remotes = data.get("remotes")
        if not isinstance(remotes, list):
            return BaseEcosystem._err(content, ecosystem, "a remotes.json without a remotes list")
        sources = [
            f"remote {r.get('name')} {r.get('url')}"
            + ("" if r.get("verify_ssl", True) else " (TLS not verified)")
            for r in remotes
            if isinstance(r, dict) and isinstance(r.get("url"), str) and not r.get("disabled")
        ]
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class ConanWorkspace:
    """conanws.yml (Conan 2 workspaces): the packages developed together, by path."""

    @staticmethod
    def members(content: FileContent) -> set[str]:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError:
            return set()
        packages = data.get("packages") if isinstance(data, dict) else None
        out: set[str] = set()
        for package in packages if isinstance(packages, list) else []:
            path = (
                package.get("path")
                if isinstance(package, dict)
                else package
                if isinstance(package, str)
                else None
            )
            if isinstance(path, str):
                out.add(path.removeprefix("./").rstrip("/"))
        return out

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid conanws.yml: {exc}")
        if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
            return BaseEcosystem._err(content, ecosystem, "a conanws.yml without a packages list")
        members = sorted(ConanWorkspace.members(content))
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            sources=(f"workspace packages {', '.join(members)}",) if members else (),
        )


class ConanEcosystem(BaseEcosystem):
    """Conan 1 and 2: recipes, consumers, locks, profiles and remotes."""

    id = "conan"
    purl_type = "conan"
    manifest_globs: tuple[str, ...] = (
        "**/conanfile.txt",
        "**/conanfile.py",
        "**/profiles/default",
        "**/conan/profiles/*",
        "**/remotes.json",
        "**/conanws.yml",
        "**/conanws.yaml",
    )
    lockfile_globs: tuple[str, ...] = ("**/conan.lock",)
    registry_hosts: frozenset[str] = frozenset({"center.conan.io", "center2.conan.io", "conan.io"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """`?user=..&channel=..&package_id=..&prev=..`: the recipe's namespace and the binary."""
        found: dict[str, str] = {}
        for condition in platform:
            key, _, value = condition.partition(" ")
            if key in ("user", "channel", "package_id", "prev") and value and " " not in value:
                found.setdefault(key, value)
        return ("?" + "&".join(f"{k}={v}" for k, v in sorted(found.items()))) if found else ""

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A package of a Conan workspace (`conanws.yml` lists it) is resolved by the workspace
        root's lock."""
        manifest = self.parse_manifest(content)
        if content.basename not in ("conanfile.py", "conanfile.txt") or manifest.parse_error:
            return manifest
        directory = content.path.rpartition("/")[0]
        ancestor = directory
        while ancestor:
            ancestor = ancestor.rpartition("/")[0]
            prefix = f"{ancestor}/" if ancestor else ""
            workspace = files.get(f"{prefix}conanws.yml") or files.get(f"{prefix}conanws.yaml")
            if workspace is None:
                continue
            relative = directory[len(prefix) :]
            if relative in ConanWorkspace.members(workspace):
                return dataclasses.replace(manifest, locked_by=ancestor)
        return manifest

    def parse_manifest(self, content: FileContent) -> Manifest:
        basename = content.basename
        if basename in ("conanws.yml", "conanws.yaml"):
            return ConanWorkspace.parse(content, self.id)
        if basename == "conanfile.py":
            return ConanRecipe.parse(content, self.id)
        if basename == "conanfile.txt":
            return ConanText.parse(content, self.id)
        if basename == "remotes.json":
            return ConanRemotes.parse(content, self.id)
        return ConanProfile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return ConanLock.parse(content, self.id)


__all__ = [
    "ConanEcosystem",
    "ConanLock",
    "ConanProfile",
    "ConanRecipe",
    "ConanRemotes",
    "ConanText",
    "Reference",
]
