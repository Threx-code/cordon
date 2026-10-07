"""opam / OCaml: opam files, opam lock files, and dune's package declarations and lock.

```
  app.opam, opam       a package: depends / depopts formulas (`"fmt" {>= "0.9" & with-test}`,
                       alternatives with `|`, groups), depexts (system packages, filtered by
                       os-family), pin-depends (a package fetched from git or an archive), build /
                       install commands, available, dev-repo
  app.opam.locked      `opam lock`: every package of the installed solution with `{= "version"}`,
                       test and doc ones flagged, pins kept as pin-depends
  dune-project         `(package (name ..) (depends ..))`, from which dune generates the opam
                       files when `(generate_opam_files true)`
  dune-workspace       contexts and the opam switches they build in
  dune.lock/           `dune pkg lock`: lock.dune (the repositories, at a commit, the solution was
                       made from) and one <name>.<version>.pkg per package: version, depends,
                       and the archive with its checksum
```

The OCaml compiler and the virtual packages describing it (`ocaml`, `ocaml-base-compiler`,
`base-unix`, `ocaml-options-vanilla`, ...) are the switch, not something fetched for the project:
recorded as platform requirements.

opam-repository holds package definitions, not archives: every package's archive comes from its
upstream (a GitHub release, the author's site). That is the registry working as designed, and a
locked archive URL is not a departure from it -- only a pin is.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from cordon_scanner.core.models import Hook, Scope
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


COMPILER_PACKAGES: frozenset[str] = frozenset(
    {
        "ocaml",
        "ocaml-base-compiler",
        "ocaml-variants",
        "ocaml-system",
        "ocaml-config",
        "ocaml-compiler",
        "ocaml-beta",
        "compiler-cloning",
        "dkml-base-compiler",
        "flexdll",
    }
)


class Switch:
    """What an opam switch provides itself."""

    @staticmethod
    def is_compiler(name: str, version: str = "") -> bool:
        """The switch's compiler and the virtual packages describing it."""
        return (
            name in COMPILER_PACKAGES
            or name.startswith(
                (
                    "base-",
                    "ocaml-option-",
                    "ocaml-options-",
                    "host-arch-",
                    "host-system-",
                    "system-",
                    "arch-",
                    "ocaml-env-",
                )
            )
            or version in ("base", "enabled")
        )


class OpamError(ValueError):
    """An opam file that is not well formed. The message never repeats the file's content."""


# -- the opam file format -------------------------------------------------------------------


@dataclass
class Node:
    """One value: `str` and `ident` atoms, `list` and `group`, `binop` / `unop`, with `options`
    the `{...}` block that follows an atom."""

    kind: str
    text: str = ""
    items: list[Node] = field(default_factory=list)
    options: list[Node] = field(default_factory=list)


class OpamLexer:
    SYMBOLS: ClassVar[tuple[str, ...]] = (
        "!=",
        "<=",
        ">=",
        "[",
        "]",
        "{",
        "}",
        "(",
        ")",
        ":",
        "&",
        "|",
        "!",
        "=",
        "<",
        ">",
        "?",
    )
    IDENT: ClassVar[re.Pattern[str]] = re.compile(
        r"[A-Za-z0-9_][A-Za-z0-9_+\-.~]*(?::[A-Za-z_][A-Za-z0-9_+\-.~]*)*"
    )
    """An identifier, with a package variable's `pkg:var` form: a colon joins only when a letter
    follows it, so `depends:` stays a field name and its colon."""
    MAX_TOKENS: ClassVar[int] = 500_000

    @staticmethod
    def tokens(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        index, length = 0, len(text)
        while index < length:
            char = text[index]
            if char.isspace():
                index += 1
            elif char == "#":
                end = text.find("\n", index)
                index = length if end < 0 else end
            elif text.startswith("(*", index):
                end = text.find("*)", index + 2)
                if end < 0:
                    raise OpamError("an unterminated comment")
                index = end + 2
            elif text.startswith('"""', index):
                end = text.find('"""', index + 3)
                if end < 0:
                    raise OpamError("an unterminated string")
                out.append(("str", text[index + 3 : end]))
                index = end + 3
            elif char == '"':
                index += 1
                buffer: list[str] = []
                while True:
                    if index >= length:
                        raise OpamError("an unterminated string")
                    current = text[index]
                    if current == "\\" and index + 1 < length:
                        buffer.append(text[index + 1])
                        index += 2
                        continue
                    if current == '"':
                        index += 1
                        break
                    buffer.append(current)
                    index += 1
                out.append(("str", "".join(buffer)))
            else:
                symbol = next((s for s in OpamLexer.SYMBOLS if text.startswith(s, index)), None)
                if symbol is not None:
                    out.append(("sym", symbol))
                    index += len(symbol)
                    continue
                found = OpamLexer.IDENT.match(text, index)
                if not found:
                    raise OpamError("a character that is not part of the opam format")
                out.append(("ident", found.group(0)))
                index = found.end()
            if len(out) > OpamLexer.MAX_TOKENS:
                raise OpamError("more tokens than an opam file holds")
        return out


class OpamParser:
    """`field: value` and `section ["name"] { ... }`, values with the opam formula operators."""

    MAX_DEPTH: ClassVar[int] = 64
    BINOPS: ClassVar[tuple[str, ...]] = ("|", "&", "=", "!=", "<", ">", "<=", ">=")
    RELOPS: ClassVar[frozenset[str]] = frozenset({"=", "!=", "<", ">", "<=", ">="})

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        position = self.index + offset
        return self.tokens[position] if position < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise OpamError("the file ends inside a value")
        self.index += 1
        return token

    def expect(self, symbol: str) -> None:
        token = self.take()
        if token != ("sym", symbol):
            raise OpamError("a bracket or brace that does not close")

    def file(self) -> dict[str, list[Node]]:
        """Fields by name (a name may repeat across sections; the top level's come first)."""
        fields: dict[str, list[Node]] = {}
        self._items(fields, top=True, depth=0)
        return fields

    def _items(self, fields: dict[str, list[Node]], top: bool, depth: int) -> None:
        if depth > OpamParser.MAX_DEPTH:
            raise OpamError("sections nested too deeply")
        while (token := self.peek()) is not None:
            if token == ("sym", "}") and not top:
                return
            kind, text = self.take()
            if kind != "ident":
                raise OpamError("a field that does not start with its name")
            following = self.peek()
            if following == ("sym", ":"):
                self.take()
                fields.setdefault(text, []).append(self.expression(0))
                continue
            # A section: `url {`, `extra-source "file" {`.
            if following is not None and following[0] == "str":
                self.take()
            self.expect("{")
            inner: dict[str, list[Node]] = {}
            self._items(inner, top=False, depth=depth + 1)
            self.expect("}")
            fields.setdefault(f"section:{text}", []).append(
                Node("section", text, items=[Node("field", k, items=v) for k, v in inner.items()])
            )

    PRECEDENCE: ClassVar[dict[str, int]] = {
        "|": 1,
        "&": 2,
        "=": 3,
        "!=": 3,
        "<": 3,
        ">": 3,
        "<=": 3,
        ">=": 3,
    }

    def expression(self, depth: int, floor: int = 1) -> Node:
        """Precedence climbing: a relation binds tighter than `&`, and `&` tighter than `|`."""
        if depth > OpamParser.MAX_DEPTH:
            raise OpamError("a value nested too deeply")
        left = self.unary(depth)
        while (
            (token := self.peek()) is not None
            and token[0] == "sym"
            and OpamParser.PRECEDENCE.get(token[1], 0) >= floor
        ):
            self.take()
            right = self.expression(depth + 1, OpamParser.PRECEDENCE[token[1]] + 1)
            left = Node("binop", token[1], items=[left, right])
        return left

    def unary(self, depth: int) -> Node:
        token = self.peek()
        if token is None:
            raise OpamError("the file ends inside a value")
        if token[0] == "sym" and token[1] in {"!", "?"} | OpamParser.RELOPS:
            self.take()
            return Node("unop", token[1], items=[self.unary(depth + 1)])
        return self.primary(depth)

    def primary(self, depth: int) -> Node:
        kind, text = self.take()
        if kind in ("str", "ident"):
            node = Node(kind, text)
        elif (kind, text) == ("sym", "["):
            node = Node("list", items=self.sequence("]", depth + 1))
        elif (kind, text) == ("sym", "("):
            node = Node("group", items=self.sequence(")", depth + 1))
        else:
            raise OpamError("a value that starts with an operator")
        if self.peek() == ("sym", "{"):
            self.take()
            node.options = self.sequence("}", depth + 1)
        return node

    def sequence(self, close: str, depth: int) -> list[Node]:
        items: list[Node] = []
        while self.peek() != ("sym", close):
            if self.peek() is None:
                raise OpamError("a bracket or brace that does not close")
            items.append(self.expression(depth))
        self.take()
        return items


class Filtered(NamedTuple):
    constraint: str
    exact: str | None
    scope: Scope | None
    conditions: tuple[str, ...]
    flag: str | None


class Formula:
    """Reading what a depends formula and its filters say."""

    FLAGS: ClassVar[dict[str, Scope]] = {
        "with-test": Scope.TEST,
        "with-doc": Scope.DEV,
        "with-dev-setup": Scope.DEV,
        "dev": Scope.DEV,
        "build": Scope.BUILD,
        "post": Scope.RUNTIME,
    }

    @staticmethod
    def render(node: Node) -> str:
        if node.kind == "str":
            text = f'"{node.text}"'
        elif node.kind == "ident":
            text = node.text
        elif node.kind in ("list", "group"):
            inner = " ".join(Formula.render(n) for n in node.items)
            text = f"[{inner}]" if node.kind == "list" else f"({inner})"
        elif node.kind == "unop":
            text = (
                f"{node.text} {Formula.render(node.items[0])}"
                if node.text in OpamParser.RELOPS
                else f"{node.text}{Formula.render(node.items[0])}"
            )
        elif node.kind == "binop":
            text = f"{Formula.render(node.items[0])} {node.text} {Formula.render(node.items[1])}"
        else:
            text = ""
        return text

    @staticmethod
    def packages(node: Node, alternative: bool = False) -> Iterator[tuple[str, list[Node], bool]]:
        """`(name, options, one-of-alternatives)` for every package a formula names."""
        if node.kind == "str":
            yield node.text, node.options, alternative
        elif node.kind in ("list", "group"):
            for item in node.items:
                yield from Formula.packages(item, alternative)
        elif node.kind == "binop" and node.text in ("|", "&"):
            for item in node.items:
                yield from Formula.packages(item, alternative or node.text == "|")

    @staticmethod
    def conjuncts(nodes: list[Node]) -> Iterator[Node]:
        for node in nodes:
            if node.kind == "binop" and node.text == "&":
                yield from Formula.conjuncts(node.items)
            else:
                yield node

    @staticmethod
    def options(options: list[Node]) -> Filtered:
        """What a `{...}` block says: the version constraint, an exact version, the scope its flag
        gives, variable conditions, and the flag itself."""
        constraints: list[str] = []
        exact: str | None = None
        scope: Scope | None = None
        flag: str | None = None
        conditions: list[str] = []
        for node in Formula.conjuncts(options):
            if (
                node.kind == "unop"
                and node.text in OpamParser.RELOPS
                and node.items[0].kind in ("str", "ident")
            ):
                # `>= "1.0"`, or `= version`: the package's own version, a variable.
                constraints.append(f"{node.text} {node.items[0].text}")
                if node.text == "=" and node.items[0].kind == "str":
                    exact = node.items[0].text
            elif node.kind == "ident" and node.text in Formula.FLAGS:
                scope = Formula.FLAGS[node.text]
                flag = node.text
            else:
                # A variable filter (`os = "linux"`, `!with-test`, `arch != "arm32"`).
                conditions.append(Formula.render(node).replace('"', ""))
        return Filtered(" & ".join(constraints) or "*", exact, scope, tuple(conditions), flag)


@dataclass
class OpamDocument:
    fields: dict[str, list[Node]]

    def first(self, name: str) -> Node | None:
        values = self.fields.get(name)
        return values[0] if values else None

    def string(self, name: str) -> str | None:
        node = self.first(name)
        return node.text if node is not None and node.kind == "str" else None

    @staticmethod
    def load(content: FileContent) -> OpamDocument:
        return OpamDocument(OpamParser(OpamLexer.tokens(content.text)).file())

    def pins(self) -> dict[str, str]:
        """`pin-depends`: `name -> source` (`[["pkg.version" "url"] ...]`, or a single pair)."""
        node = self.first("pin-depends")
        if node is None or node.kind != "list":
            return {}
        pairs = node.items if node.items and node.items[0].kind == "list" else [node]
        out: dict[str, str] = {}
        for pair in pairs:
            strings = [n.text for n in pair.items if n.kind == "str"]
            if len(strings) >= 2:
                package = strings[0].partition(".")[0] if "." in strings[0] else strings[0]
                out[package] = OpamDocument.source(strings[1])
        return out

    @staticmethod
    def source(url: str) -> str:
        if url.startswith(("file://", "/", "./", "../")):
            return f"path:{url.removeprefix('file://')}"
        return url

    def hooks(self, path: str, ecosystem: str) -> tuple[Hook, ...]:
        """`build:` and `install:` commands run when the package is installed."""
        out: list[Hook] = []
        for name in ("build", "install"):
            node = self.first(name)
            if node is None or node.kind != "list" or not node.items:
                continue
            commands = node.items if node.items[0].kind == "list" else [node]
            # The first command every install runs: `["dune" "subst"] {dev}` runs only when
            # building from a source checkout.
            runs = [
                c
                for c in commands
                if not any(
                    o.kind == "ident" and o.text == "dev" for o in Formula.conjuncts(c.options)
                )
            ]
            if not runs:
                continue
            words = [n.text for n in runs[0].items if n.kind in ("str", "ident")][:6]
            out.append(
                Hook(
                    kind="build",
                    path=path,
                    name=f"opam {name}",
                    command=" ".join(words),
                    ecosystem=ecosystem,
                )
            )
        return tuple(out)


class OpamFile:
    """An opam package file (`app.opam`, `opam`)."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            document = OpamDocument.load(content)
        except OpamError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable opam file: {exc}")
        if "opam-version" not in document.fields and "depends" not in document.fields:
            return BaseEcosystem._err(
                content, ecosystem, "an opam file with neither opam-version nor depends"
            )
        pins = document.pins()
        declared: list[DeclaredDependency] = []
        for field_name, default in (("depends", Scope.RUNTIME), ("depopts", Scope.OPTIONAL)):
            for node in document.fields.get(field_name, []):
                for name, options, alternative in Formula.packages(node):
                    filtered = Formula.options(options)
                    scope = (
                        Scope.PLATFORM if Switch.is_compiler(name) else filtered.scope or default
                    )
                    pinned = pins.get(name)
                    note = None
                    if alternative:
                        note = "one of alternatives (`|`): resolved only if the solver chooses it"
                    elif filtered.flag in ("with-test", "with-doc", "with-dev-setup", "dev"):
                        note = f"a {filtered.flag} dependency: installed, and locked, only when opam is asked for {filtered.flag}"
                    declared.append(
                        DeclaredDependency(
                            name=name,
                            spec=pinned if pinned else filtered.constraint,
                            scope=scope,
                            field_name=field_name,
                            platform=filtered.conditions,
                            note=note,
                        )
                    )
        for node in document.fields.get("depexts", []):
            for system, conditions in OpamFile.depexts(node):
                declared.append(
                    DeclaredDependency(
                        name=f"depext:{system}",
                        spec="*",
                        scope=Scope.PLATFORM,
                        field_name="depexts",
                        platform=conditions,
                    )
                )
        sources: list[str] = []
        available = document.first("available")
        if available is not None:
            sources.append(f"available: {Formula.render(available).replace(chr(34), '')}")
        basename = content.basename
        package_name = document.string("name") or (
            basename.removesuffix(".opam") if basename != "opam" else None
        )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=package_name,
            version=document.string("version"),
            dependencies=tuple(declared),
            hooks=document.hooks(content.path, ecosystem),
            sources=tuple(sources),
            source_patterns=pins,
            repository=document.string("dev-repo"),
        )

    @staticmethod
    def depexts(node: Node) -> Iterator[tuple[str, tuple[str, ...]]]:
        """opam 2's `depexts: [["pkg" ...] {filter} ...]` (or a single such list)."""
        groups = (
            node.items
            if node.kind == "list" and node.items and node.items[0].kind == "list"
            else [node]
        )
        for group in groups:
            conditions = Formula.options(group.options).conditions
            for item in group.items:
                if item.kind == "str":
                    yield item.text, conditions


class OpamLock:
    """`*.opam.locked`: the solution `opam lock` recorded, one exact version per package."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            document = OpamDocument.load(content)
        except OpamError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable opam lock file: {exc}",
            )
        depends = document.fields.get("depends")
        if not depends:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an opam lock file without depends",
            )
        pins = document.pins()
        entries: list[LockEntry] = []
        for node in depends:
            for name, options, _alternative in Formula.packages(node):
                filtered = Formula.options(options)
                exact, flagged, conditions = filtered.exact, filtered.scope, filtered.conditions
                if exact is None:
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error="a locked dependency without an exact version",
                    )
                pinned = pins.get(name)
                entries.append(
                    LockEntry(
                        name=name,
                        version=exact,
                        scope=Scope.PLATFORM
                        if Switch.is_compiler(name, exact)
                        else flagged or Scope.RUNTIME,
                        # A pin's source; anything else comes through opam-repository.
                        resolved_from=pinned
                        if pinned and not Switch.is_compiler(name, exact)
                        else None,
                        local=bool(pinned and pinned.startswith("path:")),
                        platform=conditions,
                    )
                )
        if not content.text.rstrip().endswith("]"):
            # `opam lock` ends the file with a closing bracket (depends, pin-depends, ...).
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an opam lock file that does not end where opam lock ends it",
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


# -- dune ------------------------------------------------------------------------------------


class Sexp:
    """S-expressions as dune writes them: atoms, "strings", `;` line comments, `#| |#` blocks
    and `#;` datum comments."""

    MAX_DEPTH: ClassVar[int] = 64
    ATOM: ClassVar[re.Pattern[str]] = re.compile(r'[^\s()";]+')

    @staticmethod
    def parse(text: str) -> list[object]:
        stack: list[list[object]] = [[]]
        skip_next: list[int] = []
        index, length = 0, len(text)
        while index < length:
            char = text[index]
            if char.isspace():
                index += 1
            elif char == ";":
                end = text.find("\n", index)
                index = length if end < 0 else end
            elif text.startswith("#|", index):
                end = text.find("|#", index + 2)
                if end < 0:
                    raise ValueError("an unterminated block comment")
                index = end + 2
            elif text.startswith("#;", index):
                skip_next.append(len(stack))
                index += 2
            elif char == "(":
                if len(stack) > Sexp.MAX_DEPTH:
                    raise ValueError("nested too deeply")
                stack.append([])
                index += 1
            elif char == ")":
                if len(stack) == 1:
                    raise ValueError("a closing parenthesis with nothing open")
                done = stack.pop()
                Sexp._add(stack, skip_next, done)
                index += 1
            elif char == '"':
                index += 1
                buffer: list[str] = []
                while index < length and text[index] != '"':
                    if text[index] == "\\" and index + 1 < length:
                        buffer.append(text[index + 1])
                        index += 2
                        continue
                    buffer.append(text[index])
                    index += 1
                if index >= length:
                    raise ValueError("an unterminated string")
                index += 1
                Sexp._add(stack, skip_next, "".join(buffer))
            else:
                found = Sexp.ATOM.match(text, index)
                if not found:
                    raise ValueError("an unreadable character")
                Sexp._add(stack, skip_next, found.group(0))
                index = found.end()
        if len(stack) != 1:
            raise ValueError("a parenthesis that does not close")
        return stack[0]

    @staticmethod
    def _add(stack: list[list[object]], skip_next: list[int], value: object) -> None:
        if skip_next and skip_next[-1] == len(stack):
            skip_next.pop()
            return
        stack[-1].append(value)

    @staticmethod
    def field(form: list[object], name: str) -> list[object] | None:
        for item in form:
            if isinstance(item, list) and item and item[0] == name:
                return item
        return None


class DuneProject:
    FLAGS: ClassVar[dict[str, Scope]] = {
        ":with-test": Scope.TEST,
        ":with-doc": Scope.DEV,
        ":with-dev-setup": Scope.DEV,
        ":build": Scope.BUILD,
        ":dev": Scope.DEV,
        ":post": Scope.RUNTIME,
    }

    @staticmethod
    def constraint(form: object) -> tuple[list[str], Scope | None, list[str]]:
        """`(constraints, scope, conditions)` of a dune dependency constraint."""
        if isinstance(form, str):
            return ([], DuneProject.FLAGS.get(form), [])
        if not isinstance(form, list) or not form:
            return ([], None, [])
        head = form[0]
        if head in ("and", "or"):
            constraints: list[str] = []
            scope: Scope | None = None
            conditions: list[str] = []
            for part in form[1:]:
                c, s, k = DuneProject.constraint(part)
                constraints += c
                scope = scope or s
                conditions += k
            joiner = " & " if head == "and" else " | "
            return ([joiner.join(constraints)] if constraints else [], scope, conditions)
        if (
            head in ("=", "<>", "<", ">", "<=", ">=")
            and len(form) == 3
            and isinstance(form[1], str)
            and form[1].startswith(":")
        ):
            # `(= :os linux)`: a variable filter.
            return ([], None, [f"{form[1][1:]} {head} {form[2]}"])
        if head in ("=", "<>", "<", ">", "<=", ">=") and len(form) == 2:
            operator = "!=" if head == "<>" else head
            return ([f"{operator} {form[1]}"], None, [])
        return ([], None, [])

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable dune-project: {exc}")
        if not any(isinstance(f, list) and f[:1] == ["lang"] for f in forms):
            return BaseEcosystem._err(
                content, ecosystem, "a dune-project without its `(lang dune ...)` line"
            )
        generated = any(
            isinstance(f, list) and f[:2] == ["generate_opam_files", "true"] for f in forms
        )
        declared: list[DeclaredDependency] = []
        names: list[str] = []
        for form in forms:
            if not (isinstance(form, list) and form[:1] == ["package"]):
                continue
            name_form = Sexp.field(form, "name")
            if name_form and len(name_form) > 1 and isinstance(name_form[1], str):
                names.append(name_form[1])
            for field_name, default in (("depends", Scope.RUNTIME), ("depopts", Scope.OPTIONAL)):
                listed = Sexp.field(form, field_name) or []
                for item in listed[1:]:
                    package = (
                        item
                        if isinstance(item, str)
                        else item[0]
                        if isinstance(item, list) and item and isinstance(item[0], str)
                        else None
                    )
                    if package is None:
                        continue
                    constraints: list[str] = []
                    scope: Scope | None = None
                    conditions: list[str] = []
                    for part in item[1:] if isinstance(item, list) else []:
                        c, s, k = DuneProject.constraint(part)
                        constraints += c
                        scope = scope or s
                        conditions += k
                    flags = [
                        p
                        for p in (item[1:] if isinstance(item, list) else [])
                        if isinstance(p, str) and p.startswith(":")
                    ]
                    note = None
                    if package == "dune":
                        note = "dune itself, which runs the build: dune's own lock leaves it out"
                    elif any(f in (":with-test", ":with-doc", ":with-dev-setup") for f in flags):
                        flag = next(
                            f for f in flags if f in (":with-test", ":with-doc", ":with-dev-setup")
                        )[1:]
                        note = f"a {flag} dependency: installed, and locked, only when asked for {flag}"
                    declared.append(
                        DeclaredDependency(
                            name=package,
                            spec=" & ".join(constraints) or "*",
                            scope=Scope.PLATFORM
                            if Switch.is_compiler(package)
                            else scope or default,
                            field_name=f"dune-project {field_name}",
                            platform=tuple(conditions),
                            note=note,
                        )
                    )
        sources = (
            [f"dune generates {', '.join(n + '.opam' for n in names)} (generate_opam_files)"]
            if generated and names
            else []
        )
        routed: dict[str, str] = {}
        for form in forms:
            if isinstance(form, list) and form[:1] == ["pin"]:
                url = Sexp.field(form, "url")
                pinned_package = Sexp.field(form, "package")
                name_form = Sexp.field(pinned_package, "name") if pinned_package else None
                if url and len(url) > 1 and name_form and len(name_form) > 1:
                    routed[str(name_form[1])] = OpamDocument.source(str(url[1]))
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=names[0] if len(names) == 1 else None,
            dependencies=tuple(declared),
            sources=tuple(sources),
            source_patterns=routed,
        )


class DuneWorkspace:
    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable dune-workspace: {exc}")
        sources: list[str] = []
        for form in forms:
            if isinstance(form, list) and form[:1] == ["context"] and len(form) > 1:
                body = form[1]
                if isinstance(body, list) and body[:1] == ["opam"]:
                    switch = Sexp.field(body, "switch")
                    sources.append(
                        f"context on opam switch {switch[1]}"
                        if switch and len(switch) > 1
                        else "context on an opam switch"
                    )
                elif body == "default" or (isinstance(body, list) and body[:1] == ["default"]):
                    sources.append("context default")
            elif isinstance(form, list) and form[:1] == ["repository"]:
                url = Sexp.field(form, "url") or Sexp.field(form, "source")
                name = Sexp.field(form, "name")
                if url and len(url) > 1:
                    sources.append(
                        f"repository {name[1] if name and len(name) > 1 else ''} {url[1]}".replace(
                            "  ", " "
                        )
                    )
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class DuneLock:
    """`dune.lock/`: lock.dune and a <name>.<version>.pkg per package."""

    @staticmethod
    def repositories(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable lock.dune: {exc}")
        sources: list[str] = []
        repositories = Sexp.field(forms, "repositories")
        used = Sexp.field(repositories, "used") if repositories else None
        for entry in (used or [])[1:]:
            source = Sexp.field(entry, "source") if isinstance(entry, list) else None
            if source and len(source) > 1:
                sources.append(f"repository {source[1]}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))

    @staticmethod
    def names(form: object) -> Iterator[str]:
        """Package names in a depends form: `(all_platforms (a b))` or a per-platform choice."""
        if isinstance(form, str):
            if not form.startswith(("all_platforms", "choice", ":", "(")):
                yield form
            return
        if isinstance(form, list):
            for item in form:
                if isinstance(item, list) and item[:1] in (
                    ["os"],
                    ["arch"],
                    ["os-family"],
                    ["os-distribution"],
                ):
                    continue
                yield from DuneLock.names(item)

    @staticmethod
    def package(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable dune lock package: {exc}",
                owner_levels=1,
            )
        version_form = Sexp.field(forms, "version")
        if not version_form or len(version_form) < 2 or not isinstance(version_form[1], str):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a dune lock package without its version",
                owner_levels=1,
            )
        version = version_form[1]
        stem = content.basename.removesuffix(".pkg")
        name = (
            stem[: -(len(version) + 1)] if stem.endswith("." + version) else stem.partition(".")[0]
        )
        depends = Sexp.field(forms, "depends")
        children = tuple(dict.fromkeys(DuneLock.names(depends[1:]))) if depends else ()
        source = Sexp.field(forms, "source")
        fetch = Sexp.field(source, "fetch") if source else None
        url = Sexp.field(fetch, "url") if fetch else None
        checksum = Sexp.field(fetch, "checksum") if fetch else None
        digest = str(checksum[1]).replace("=", ":", 1) if checksum and len(checksum) > 1 else None
        pinned = Sexp.field(forms, "dev") is not None
        location = str(url[1]) if url and len(url) > 1 else None
        compiler = Switch.is_compiler(name, version)
        entry = LockEntry(
            name=name,
            version=version,
            integrity=digest,
            # Only a pin (`(dev)`) departs from opam-repository; an archive URL is the registry's.
            resolved_from=OpamDocument.source(location) if pinned and location else None,
            scope=Scope.PLATFORM if compiler else Scope.RUNTIME,
            dependencies=children,
        )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=(entry,), owner_levels=1)


class OpamEcosystem(BaseEcosystem):
    """OCaml packages through opam and dune."""

    id = "opam"
    purl_type = "opam"
    manifest_globs: tuple[str, ...] = (
        "**/*.opam",
        "**/opam",
        "**/dune-project",
        "**/dune-workspace",
        "**/dune.lock/lock.dune",
    )
    lockfile_globs: tuple[str, ...] = ("**/*.opam.locked", "**/dune.lock/*.pkg")
    registry_hosts: frozenset[str] = frozenset(
        {"opam.ocaml.org", "github.com/ocaml/opam-repository"}
    )
    records_integrity = False
    """`opam lock` records no hashes: opam checks every archive against the checksum in
    opam-repository's own definition of the package. dune's lock does record each archive's
    checksum, and those are kept and judged (a malformed one is reported); a missing one is the
    format, not a gap."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A dune project inside a dune workspace is resolved by the workspace root's lock: dune
        builds every project under the dune-workspace as one, from one dune.lock/."""
        manifest = self.parse_manifest(content)
        if content.basename != "dune-project" and not content.basename.endswith(".opam"):
            return manifest
        directory = content.path.rpartition("/")[0]
        ancestor = directory
        while ancestor:
            ancestor = ancestor.rpartition("/")[0]
            prefix = f"{ancestor}/" if ancestor else ""
            if f"{prefix}dune-workspace" in files and any(
                p.startswith(f"{prefix}dune.lock/") for p in files
            ):
                if manifest.parse_error is None:
                    return dataclasses.replace(manifest, locked_by=ancestor)
                return manifest
        return manifest

    def parse_manifest(self, content: FileContent) -> Manifest:
        basename = content.basename
        if basename == "dune-project":
            return DuneProject.parse(content, self.id)
        if basename == "dune-workspace":
            return DuneWorkspace.parse(content, self.id)
        if basename == "lock.dune":
            return DuneLock.repositories(content, self.id)
        return OpamFile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename.endswith(".pkg"):
            return DuneLock.package(content, self.id)
        return OpamLock.parse(content, self.id)


__all__ = [
    "COMPILER_PACKAGES",
    "DuneLock",
    "DuneProject",
    "DuneWorkspace",
    "Formula",
    "OpamEcosystem",
    "OpamFile",
    "OpamLexer",
    "OpamLock",
    "OpamParser",
    "Sexp",
    "Switch",
]
