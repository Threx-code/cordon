"""Hackage / Haskell: Cabal and Stack, kept distinct.

```
  *.cabal               the package: components (library, executable, test-suite, benchmark,
                        foreign-library, custom-setup), `common` stanzas pulled in by `import:`,
                        `flag` declarations, and `if` / `elif` / `else` conditionals around
                        build-depends, build-tool-depends, pkgconfig-depends
  package.yaml          hpack's description of the same, which Stack turns into the .cabal file
  cabal.project         Cabal's project: constraints (forced versions and flags),
                        source-repository-package (git), repository (other indices),
                        with-compiler, index-state
  cabal.project.freeze  Cabal's lock: `any.<pkg> ==<version>` for every package of the install
                        plan, flag assignments, and the index-state that fixes metadata revisions
  stack.yaml            Stack's project: the snapshot (resolver), extra-deps (Hackage pins with a
                        revision, git, archives), flags, compiler, package indices
  stack.yaml.lock       Stack's lock: each extra-dep completed with the SHA-256 of its cabal-file
                        revision (or its commit), and the snapshot by hash
```

The two tools resolve differently and are never merged: Cabal's freeze lists the whole plan, while
Stack's lock lists only the extra-deps -- every other package comes from the snapshot, which the
lock pins by hash without naming its packages. A declaration Stack resolves from the snapshot says
so rather than reading as missing from the lock.

Packages that are part of GHC itself (`base`, `ghc-prim`, `rts`, ...) cannot be installed from
Hackage: they are recorded as platform requirements the compiler meets.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)
from cordon_scanner.foundation.formats.datayaml import DataYaml
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.foundation.content import FileContent


GHC_PACKAGES: frozenset[str] = frozenset(
    {
        "base",
        "ghc",
        "ghc-bignum",
        "ghc-boot-th",
        "ghc-heap",
        "ghc-internal",
        "ghc-prim",
        "ghci",
        "integer-gmp",
        "integer-simple",
        "rts",
        "system-cxx-std-lib",
        "template-haskell",
    }
)
"""Packages that ship inside GHC and cannot be installed from Hackage: the compiler's own."""


@dataclass
class CabalNode:
    """A field (`name: value`) or a section (`library`, `if os(windows)`) of a Cabal-format file."""

    head: str
    value: str = ""
    children: list[CabalNode] = field(default_factory=list)
    is_field: bool = True


class CabalLayout:
    """The indentation-structured format of .cabal and cabal.project files.

    A field's value continues on every following line indented further than the field; a
    section's body is every following line indented further than its header. Comments are whole
    lines starting with `--`.
    """

    FIELD: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:(.*)$")
    MAX_DEPTH: ClassVar[int] = 32

    @staticmethod
    def parse(text: str) -> list[CabalNode]:
        lines = [
            (len(line) - len(line.lstrip(" \t")), line.strip(), number)
            for number, line in enumerate(text.splitlines(), start=1)
            if line.strip() and not line.strip().startswith("--")
        ]
        nodes, index = CabalLayout._block(lines, 0, -1, 0)
        if index != len(lines):
            raise ValueError(f"line {lines[index][2]}: unexpected indentation")
        return nodes

    @staticmethod
    def _block(
        lines: list[tuple[int, str, int]], index: int, floor: int, depth: int
    ) -> tuple[list[CabalNode], int]:
        if depth > CabalLayout.MAX_DEPTH:
            raise ValueError(f"sections nested deeper than {CabalLayout.MAX_DEPTH}")
        nodes: list[CabalNode] = []
        while index < len(lines):
            indent, text, number = lines[index]
            if indent <= floor:
                break
            if ("{" in text or "}" in text) and (
                CabalLayout.FIELD.match(text) is None or text.rstrip().endswith("{")
            ):
                raise ValueError(f"line {number}: the brace layout is not read")
            found = CabalLayout.FIELD.match(text)
            if found:
                parts = [found.group(2).strip()]
                index += 1
                while index < len(lines) and lines[index][0] > indent:
                    parts.append(lines[index][1])
                    index += 1
                nodes.append(
                    CabalNode(head=found.group(1).lower(), value="\n".join(p for p in parts if p))
                )
                continue
            children, index = CabalLayout._block(lines, index + 1, indent, depth + 1)
            nodes.append(CabalNode(head=text, children=children, is_field=False))
        return nodes, index

    @staticmethod
    def fields(nodes: list[CabalNode], name: str) -> list[str]:
        return [n.value for n in nodes if n.is_field and n.head == name]

    @staticmethod
    def first(nodes: list[CabalNode], name: str) -> str | None:
        found = CabalLayout.fields(nodes, name)
        return found[0].strip() if found else None


class CabalDeps:
    """`build-depends` entries: `name`, `name constraint`, `pkg:sublib`, `pkg:{a, b}`."""

    NAME: ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?::(?:\{[^}]*\}|[A-Za-z0-9-]+))?\s*(.*)$"
    )

    @staticmethod
    def split(value: str) -> Iterator[str]:
        depth = 0
        current = ""
        for char in value.replace("\n", " "):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            if char == "," and depth == 0:
                yield current.strip()
                current = ""
            else:
                current += char
        if current.strip():
            yield current.strip()

    @staticmethod
    def entries(value: str) -> Iterator[tuple[str, str]]:
        for chunk in CabalDeps.split(value):
            if not chunk:
                continue
            found = CabalDeps.NAME.match(chunk)
            if not found:
                raise ValueError("a build-depends entry is not `package constraint`")
            constraint = found.group(2).strip()
            yield found.group(1), "*" if constraint in ("", "-any", "any") else constraint


@dataclass
class _Collected:
    declared: dict[tuple[str, Scope], DeclaredDependency] = field(default_factory=dict)

    def add(self, dependency: DeclaredDependency) -> None:
        key = (dependency.name.lower(), dependency.scope)
        held = self.declared.get(key)
        if held is None or (held.platform and not dependency.platform):
            # Unconditional anywhere is unconditional.
            self.declared[key] = dependency


class CabalFile:
    """A package's .cabal file."""

    COMPONENTS: ClassVar[dict[str, Scope]] = {
        "library": Scope.RUNTIME,
        "foreign-library": Scope.RUNTIME,
        "executable": Scope.RUNTIME,
        "test-suite": Scope.TEST,
        "benchmark": Scope.DEV,
        "custom-setup": Scope.BUILD,
    }

    SECTIONS: ClassVar[frozenset[str]] = frozenset(
        {*COMPONENTS, "flag", "common", "source-repository"}
    )

    @staticmethod
    def _declares(
        nodes: list[CabalNode], commons: Mapping[str, list[CabalNode]], depth: int
    ) -> bool:
        """Whether a component names build-depends anywhere: directly, under a conditional, or
        in a common stanza it imports."""
        if depth > CabalLayout.MAX_DEPTH:
            return False
        for node in nodes:
            if node.is_field and node.head == "build-depends":
                return True
            if node.is_field and node.head == "import":
                imported = [i.strip() for i in node.value.replace("\n", ",").split(",")]
                if any(
                    CabalFile._declares(commons[i], commons, depth + 1)
                    for i in imported
                    if i in commons
                ):
                    return True
            if not node.is_field and CabalFile._declares(node.children, commons, depth + 1):
                return True
        return False

    @staticmethod
    def note(conditions: tuple[str, ...], flags: Mapping[str, bool]) -> str:
        """Why a conditional declaration may be absent from a lock: it applies only where its
        condition holds, and a flag that is off by default leaves it out entirely."""
        off = [
            c
            for c in conditions
            if (m := re.fullmatch(r"flag\(([^)]+)\)", c)) and flags.get(m.group(1).lower()) is False
        ]
        if off:
            return f"conditional on {' and '.join(conditions)}, a flag off by default: resolved only when it is turned on"
        return f"conditional on {' and '.join(conditions)}: resolved only where that holds"

    @staticmethod
    def parse(content: FileContent, ecosystem: str, snapshot_note: str | None) -> Manifest:
        try:
            nodes = CabalLayout.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable .cabal file: {exc}")
        name = CabalLayout.first(nodes, "name")
        version = CabalLayout.first(nodes, "version")
        if not name or not version:
            return BaseEcosystem._err(
                content, ecosystem, "a .cabal file without the required `name` and `version`"
            )
        commons = {
            n.head.split(None, 1)[1].strip(): n.children
            for n in nodes
            if not n.is_field and n.head.lower().startswith("common ") and len(n.head.split()) > 1
        }
        internal = {name.lower()} | {
            n.head.split(None, 1)[1].strip().lower()
            for n in nodes
            if not n.is_field
            and n.head.lower().split()[0] in ("library", "foreign-library")
            and len(n.head.split()) > 1
        }
        flags: dict[str, bool] = {}
        sources: list[str] = []
        CabalFile._flags_and_sources(nodes, flags, sources)
        collected = _Collected()
        if not any(
            not n.is_field and n.head.lower().split()[0] in CabalFile.COMPONENTS for n in nodes
        ):
            # Cabal refuses a package with no library or executable: one cut before its first.
            return BaseEcosystem._err(
                content,
                ecosystem,
                "a .cabal file with no component (library, executable, test-suite, benchmark)",
            )
        try:
            for node in nodes:
                if node.is_field:
                    continue
                kind = node.head.lower().split()[0]
                if kind not in CabalFile.SECTIONS:
                    # Not a section Cabal has: a field cut short (`build-dep`), or not a .cabal.
                    raise ValueError("a top-level line is neither a field nor a section")
                scope = CabalFile.COMPONENTS.get(kind)
                if scope is None:
                    continue
                if not node.children and any(
                    CabalFile._declares(other.children, commons, 0)
                    for other in nodes
                    if not other.is_field
                    and other is not node
                    and other.head.lower().split()[0] in CabalFile.COMPONENTS
                ):
                    # An empty `library` beside named sublibraries: Cabal 3 allows it, and packages
                    # write one so that other projects can depend on their internal libraries.
                    # Nothing in it to lose; a file where nothing declares anything still fails.
                    continue
                if kind != "custom-setup" and not CabalFile._declares(node.children, commons, 0):
                    # Nothing compiles without base: a component that depends on nothing is one
                    # whose build-depends was lost.
                    raise ValueError("a component without build-depends")
                CabalFile._component(
                    node.children, scope, (), commons, internal, flags, collected, snapshot_note, 0
                )
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable .cabal file: {exc}")
        tested = CabalLayout.first(nodes, "tested-with")
        if tested:
            sources.append(f"tested-with {tested}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=name,
            version=version,
            dependencies=tuple(collected.declared.values()),
            hooks=CabalFile.hooks(content.path, CabalLayout.first(nodes, "build-type"), ecosystem),
            sources=tuple(sources),
            repository=CabalFile._repository(nodes),
        )

    @staticmethod
    def _flags_and_sources(
        nodes: list[CabalNode], flags: dict[str, bool], sources: list[str]
    ) -> None:
        """Each flag's default, and the source repositories the file names."""
        for node in nodes:
            if (
                not node.is_field
                and node.head.lower().startswith("flag ")
                and len(node.head.split()) > 1
            ):
                flag = node.head.split(None, 1)[1].strip().lower()
                default = (CabalLayout.first(node.children, "default") or "true").lower() != "false"
                manual = (CabalLayout.first(node.children, "manual") or "false").lower() == "true"
                flags[flag] = default
                sources.append(
                    f"flag {flag} (default {'on' if default else 'off'}{', manual' if manual else ''})"
                )

    @staticmethod
    def hooks(path: str, build_type: str | None, ecosystem: str) -> tuple[Hook, ...]:
        """`build-type: Custom` builds through the package's own Setup.hs, and `Configure` runs
        its `./configure` script first: code of the package's, run by every build of it."""
        kind = (build_type or "").strip().lower()
        if kind == "custom":
            return (
                Hook(
                    kind="build",
                    path=path,
                    name="build-type Custom",
                    command="Setup.hs",
                    ecosystem=ecosystem,
                ),
            )
        if kind == "configure":
            return (
                Hook(
                    kind="build",
                    path=path,
                    name="build-type Configure",
                    command="configure",
                    ecosystem=ecosystem,
                ),
            )
        return ()

    @staticmethod
    def _repository(nodes: list[CabalNode]) -> str | None:
        for node in nodes:
            if not node.is_field and node.head.lower().startswith("source-repository"):
                location = CabalLayout.first(node.children, "location")
                if location:
                    return location
        return None

    @staticmethod
    def _component(
        nodes: list[CabalNode],
        scope: Scope,
        conditions: tuple[str, ...],
        commons: Mapping[str, list[CabalNode]],
        internal: set[str],
        flags: Mapping[str, bool],
        collected: _Collected,
        snapshot_note: str | None,
        depth: int,
    ) -> None:
        if depth > CabalLayout.MAX_DEPTH:
            raise ValueError("common stanzas import each other in a cycle")
        previous: str | None = None
        for node in nodes:
            if node.is_field:
                if node.head == "import":
                    for imported in (i.strip() for i in node.value.replace("\n", ",").split(",")):
                        if imported in commons:
                            CabalFile._component(
                                commons[imported],
                                scope,
                                conditions,
                                commons,
                                internal,
                                flags,
                                collected,
                                snapshot_note,
                                depth + 1,
                            )
                    continue
                CabalFile._field(node, scope, conditions, internal, flags, collected, snapshot_note)
                continue
            words = node.head.split(None, 1)
            keyword = words[0].lower()
            condition = words[1].strip() if len(words) > 1 else ""
            if keyword == "if":
                applied = (*conditions, condition)
                previous = condition
            elif keyword == "elif" and previous is not None:
                applied = (*conditions, f"!({previous})", condition)
                previous = f"({previous}) || ({condition})"
            elif keyword == "else" and previous is not None:
                applied = (*conditions, f"!({previous})")
                previous = None
            else:
                raise ValueError("a line inside a component is neither a field nor a conditional")
            CabalFile._component(
                node.children,
                scope,
                applied,
                commons,
                internal,
                flags,
                collected,
                snapshot_note,
                depth + 1,
            )

    @staticmethod
    def _field(
        node: CabalNode,
        scope: Scope,
        conditions: tuple[str, ...],
        internal: set[str],
        flags: Mapping[str, bool],
        collected: _Collected,
        snapshot_note: str | None,
    ) -> None:
        if node.head in ("build-depends", "setup-depends"):
            for name, spec in CabalDeps.entries(node.value):
                if name.lower() in internal:
                    continue
                CabalFile._add(
                    name,
                    spec,
                    Scope.PLATFORM if name in GHC_PACKAGES else scope,
                    node.head,
                    conditions,
                    flags,
                    collected,
                    snapshot_note,
                )
        elif node.head in ("build-tool-depends", "build-tools"):
            for name, spec in CabalDeps.entries(node.value):
                if name.lower() not in internal:
                    CabalFile._add(
                        name,
                        spec,
                        Scope.TOOL,
                        node.head,
                        conditions,
                        flags,
                        collected,
                        snapshot_note,
                    )
        elif node.head in ("pkgconfig-depends", "extra-libraries"):
            for name, spec in CabalDeps.entries(node.value):
                # A system library: met by the operating system, not by Hackage.
                # Named apart from the Hackage package of the same name (`zlib` binds C zlib).
                prefix = "pkg-config:" if node.head == "pkgconfig-depends" else "lib:"
                collected.add(
                    DeclaredDependency(
                        name=prefix + name,
                        spec=spec,
                        scope=Scope.PLATFORM,
                        field_name=node.head,
                        platform=conditions,
                    )
                )

    @staticmethod
    def _add(
        name: str,
        spec: str,
        scope: Scope,
        field_name: str,
        conditions: tuple[str, ...],
        flags: Mapping[str, bool],
        collected: _Collected,
        snapshot_note: str | None,
    ) -> None:
        note = CabalFile.note(conditions, flags) if conditions else snapshot_note
        collected.add(
            DeclaredDependency(
                name=name,
                spec=spec,
                scope=scope,
                field_name=field_name,
                platform=conditions,
                note=note,
            )
        )


class Hpack:
    """hpack's package.yaml: what Stack projects write instead of a .cabal file."""

    COMPONENTS: ClassVar[tuple[tuple[str, Scope, bool], ...]] = (
        ("library", Scope.RUNTIME, False),
        ("internal-libraries", Scope.RUNTIME, True),
        ("executables", Scope.RUNTIME, True),
        ("tests", Scope.TEST, True),
        ("benchmarks", Scope.DEV, True),
    )
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "library",
            "executables",
            "tests",
            "benchmarks",
            "internal-libraries",
            "source-dirs",
            "ghc-options",
            "default-extensions",
        }
    )
    HALLMARK: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:library|executables|internal-libraries|source-dirs|ghc-options|default-extensions)\s*:",
        re.MULTILINE,
    )
    """hpack's own keys, recognisable in a file too damaged to parse: the manifest detector reads
    a file without the tree around it, so a sibling stack.yaml is not always in view."""

    @staticmethod
    def is_hpack(data: Mapping[str, Any], beside_stack: bool) -> bool:
        """pnpm also reads a package.yaml; hpack's has components, or lists its dependencies."""
        if "devDependencies" in data or "scripts" in data:
            return False
        return (
            beside_stack
            or bool(Hpack.KEYS & set(data))
            or isinstance(data.get("dependencies"), list)
        )

    @staticmethod
    def entries(value: Any) -> Iterator[tuple[str, str]]:
        items: list[Any] = (
            value if isinstance(value, list) else [value] if isinstance(value, str) else []
        )
        if isinstance(value, dict):
            for name, spec in value.items():
                text = (
                    spec
                    if isinstance(spec, str)
                    else (spec.get("version") if isinstance(spec, dict) else None)
                )
                yield str(name), str(text or "*")
            return
        for item in items:
            yield from CabalDeps.entries(str(item))

    @staticmethod
    def _section(
        body: Mapping[str, Any],
        scope: Scope,
        conditions: tuple[str, ...],
        internal: set[str],
        flags: dict[str, bool],
        collected: _Collected,
        snapshot_note: str | None,
    ) -> None:
        """One section's dependencies, build tools and system libraries, and its when: clauses,
        each under its conditions."""
        for key, field_scope in (
            ("dependencies", scope),
            ("build-tools", Scope.TOOL),
            ("build-tool-depends", Scope.TOOL),
        ):
            for dep, spec in Hpack.entries(body.get(key)):
                if dep.lower() in internal:
                    continue
                applied = (
                    Scope.PLATFORM
                    if dep in GHC_PACKAGES and field_scope is not Scope.TOOL
                    else field_scope
                )
                CabalFile._add(dep, spec, applied, key, conditions, flags, collected, snapshot_note)
        for system_key in ("pkg-config-dependencies", "extra-libraries"):
            for dep, spec in Hpack.entries(body.get(system_key)):
                prefix = "pkg-config:" if system_key == "pkg-config-dependencies" else "lib:"
                collected.add(
                    DeclaredDependency(
                        name=prefix + dep,
                        spec=spec,
                        scope=Scope.PLATFORM,
                        field_name=system_key,
                        platform=conditions,
                    )
                )
        when = body.get("when")
        for clause in when if isinstance(when, list) else [when] if isinstance(when, dict) else []:
            if not isinstance(clause, dict) or not isinstance(clause.get("condition"), str):
                continue
            condition = clause["condition"]
            if isinstance(clause.get("then"), dict):
                Hpack._section(
                    clause["then"],
                    scope,
                    (*conditions, condition),
                    internal,
                    flags,
                    collected,
                    snapshot_note,
                )
                if isinstance(clause.get("else"), dict):
                    Hpack._section(
                        clause["else"],
                        scope,
                        (*conditions, f"!({condition})"),
                        internal,
                        flags,
                        collected,
                        snapshot_note,
                    )
            else:
                Hpack._section(
                    clause,
                    scope,
                    (*conditions, condition),
                    internal,
                    flags,
                    collected,
                    snapshot_note,
                )

    @staticmethod
    def parse(
        content: FileContent, ecosystem: str, data: Mapping[str, Any], snapshot_note: str | None
    ) -> Manifest:
        name = BaseEcosystem._s(data.get("name"))
        internal = {name.lower()} if name else set()
        internal |= (
            {str(k).lower() for k in (data.get("internal-libraries") or {})}
            if isinstance(data.get("internal-libraries"), dict)
            else set()
        )
        flags: dict[str, bool] = {}
        sources: list[str] = []
        if isinstance(data.get("flags"), dict):
            for flag, spec in data["flags"].items():
                default = not (isinstance(spec, dict) and spec.get("default") is False)
                flags[str(flag).lower()] = default
                sources.append(f"flag {str(flag).lower()} (default {'on' if default else 'off'})")
        collected = _Collected()

        try:
            Hpack._section(data, Scope.RUNTIME, (), internal, flags, collected, snapshot_note)
            for key, scope, named in Hpack.COMPONENTS:
                body = data.get(key)
                bodies = (
                    list(body.values())
                    if named and isinstance(body, dict)
                    else [body]
                    if not named
                    else []
                )
                for each in bodies:
                    if isinstance(each, dict):
                        Hpack._section(each, scope, (), internal, flags, collected, snapshot_note)
            setup = data.get("custom-setup")
            if isinstance(setup, dict):
                Hpack._section(setup, Scope.BUILD, (), internal, flags, collected, snapshot_note)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable package.yaml: {exc}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=name,
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(collected.declared.values()),
            # hpack writes `build-type: Custom` whenever a `custom-setup` section is present.
            hooks=CabalFile.hooks(
                content.path,
                "Custom"
                if isinstance(data.get("custom-setup"), dict)
                else BaseEcosystem._s(data.get("build-type")),
                ecosystem,
            ),
            sources=tuple(sources),
            repository=BaseEcosystem._s(data.get("github")),
        )


class HackageEcosystem(BaseEcosystem):
    """Haskell packages through Cabal and Stack."""

    id = "hackage"
    purl_type = "hackage"
    manifest_globs: tuple[str, ...] = (
        "**/*.cabal",
        "**/cabal.project",
        "**/stack.yaml",
        "**/package.yaml",
    )
    lockfile_globs: tuple[str, ...] = ("**/cabal.project.freeze", "**/stack.yaml.lock")
    registry_hosts: frozenset[str] = frozenset({"hackage.haskell.org"})
    records_integrity = False
    """A freeze file pins versions and no hashes (Cabal checks downloads against Hackage's signed
    index); Stack's lock records the cabal-file revision hash, kept where present."""

    def normalize_name(self, name: str) -> str:
        """Hackage refuses a name that differs from an existing one only in case."""
        return name.strip().lower()

    @staticmethod
    def governing_stack(
        path: str, files: Mapping[str, FileContent]
    ) -> tuple[str, Mapping[str, Any]] | None:
        """The stack.yaml of the nearest directory at or above the file, and its data."""
        from cordon_scanner.ecosystems.packages.haskell.stack import StackProject

        directory = path.rpartition("/")[0]
        while True:
            candidate = f"{directory}/stack.yaml" if directory else "stack.yaml"
            if candidate in files:
                try:
                    return candidate, StackProject.load(files[candidate])
                except ValueError:
                    return None
            if not directory:
                return None
            directory = directory.rpartition("/")[0]

    @staticmethod
    def owning_project(path: str, files: Mapping[str, FileContent]) -> str | None:
        """The directory of the cabal.project or stack.yaml above this package that lists it as
        one of its packages: the project whose lock (freeze file, stack.yaml.lock) resolves it.
        None for a package that is its own project."""
        own = path.rpartition("/")[0]
        directory = own
        while directory:
            directory = directory.rpartition("/")[0]
            relative = own[len(directory) + 1 :] if directory else own
            for name in ("cabal.project", "stack.yaml"):
                candidate = f"{directory}/{name}" if directory else name
                if candidate in files and relative in HackageEcosystem.listed_packages(
                    files[candidate], relative
                ):
                    return directory
        return None

    @staticmethod
    def listed_packages(content: FileContent, relative: str) -> set[str]:
        """Which of the project's `packages:` entries name `relative` (a directory, a glob over
        directories, or a .cabal file in it)."""
        import fnmatch

        from cordon_scanner.ecosystems.packages.haskell.stack import StackProject

        patterns: list[str] = []
        if content.basename == "cabal.project":
            try:
                nodes = CabalLayout.parse(content.text)
            except ValueError:
                return set()
            for value in CabalLayout.fields(nodes, "packages") + CabalLayout.fields(
                nodes, "optional-packages"
            ):
                patterns += value.replace(",", " ").split()
        else:
            try:
                data = StackProject.load(content)
            except ValueError:
                return set()
            listed = data.get("packages")
            patterns += (
                [str(p) for p in listed if isinstance(p, str)] if isinstance(listed, list) else []
            )
        out: set[str] = set()
        for pattern in patterns:
            text = pattern.removeprefix("./").rstrip("/")
            if text.endswith(".cabal"):
                text = text.rpartition("/")[0]
            if text and fnmatch.fnmatchcase(relative, text):
                out.add(relative)
        return out

    @staticmethod
    def snapshot_note(path: str, files: Mapping[str, FileContent], owner: str | None) -> str | None:
        from cordon_scanner.ecosystems.packages.haskell.stack import StackProject

        directory = path.rpartition("/")[0] if owner is None else owner
        freeze = f"{directory}/cabal.project.freeze" if directory else "cabal.project.freeze"
        if freeze in files:
            return None
        governing = HackageEcosystem.governing_stack(path, files)
        if governing is None:
            return None
        snapshot = StackProject.snapshot(governing[1])
        return (
            f"resolved by Stack from the {snapshot} snapshot, which stack.yaml.lock pins by hash without listing its packages"
            if snapshot
            else None
        )

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        from cordon_scanner.ecosystems.packages.haskell.cabal_project import CabalProject
        from cordon_scanner.ecosystems.packages.haskell.stack import StackProject

        basename = content.basename
        if basename == "cabal.project":
            return CabalProject.parse(content, self.id)
        if basename == "stack.yaml":
            return StackProject.parse(content, self.id)
        owner = HackageEcosystem.owning_project(content.path, files)
        note = HackageEcosystem.snapshot_note(content.path, files, owner)
        manifest = self._package(content, files, note)
        if owner is not None and manifest.parse_error is None:
            # A member of a multi-package project: the project's lock resolves it.
            return dataclasses.replace(manifest, locked_by=owner)
        return manifest

    def _package(
        self, content: FileContent, files: Mapping[str, FileContent], note: str | None
    ) -> Manifest:
        if content.basename == "package.yaml":
            # Beside a stack.yaml it is certainly hpack's, and one that cannot be read is
            # reported; elsewhere it may be pnpm's, which is not this ecosystem's to judge.
            directory = content.path.rpartition("/")[0]
            beside = (
                f"{directory}/stack.yaml" if directory else "stack.yaml"
            ) in files or Hpack.HALLMARK.search(content.text) is not None
            try:
                data = DataYaml.load(content.text, source=content.path)
            except ValueError as exc:
                return (
                    BaseEcosystem._err(content, self.id, f"invalid package.yaml: {exc}")
                    if beside
                    else Manifest(path=content.path, ecosystem=self.id)
                )
            if not isinstance(data, dict) or not Hpack.is_hpack(data, beside):
                if beside:
                    return BaseEcosystem._err(
                        content,
                        self.id,
                        "a package.yaml beside stack.yaml that is not an hpack package description",
                    )
                return Manifest(path=content.path, ecosystem=self.id)
            if beside and "name" not in data:
                return BaseEcosystem._err(
                    content, self.id, "an hpack package.yaml without a `name`"
                )
            return Hpack.parse(content, self.id, data, note)
        return CabalFile.parse(content, self.id, note)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        from cordon_scanner.ecosystems.packages.haskell.cabal_project import CabalFreeze
        from cordon_scanner.ecosystems.packages.haskell.stack import StackLock

        if content.basename == "stack.yaml.lock":
            return StackLock.parse(content, self.id)
        return CabalFreeze.parse(content, self.id)


__all__ = [
    "GHC_PACKAGES",
    "CabalDeps",
    "CabalFile",
    "CabalLayout",
    "HackageEcosystem",
    "Hpack",
]
