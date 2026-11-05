"""opam's file format: its lexer, parser, filtered formulas and the document they read, with the
compiler packages a switch provides. Read by `opam` files and by dune's lock directory alike, so
below both."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.content import FileContent


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


__all__ = [
    "COMPILER_PACKAGES",
    "Filtered",
    "Formula",
    "Node",
    "OpamDocument",
    "OpamError",
    "OpamLexer",
    "OpamParser",
    "Switch",
]
