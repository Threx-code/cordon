"""What Cabal's formats share: GHC's own packages, a dependency node, a package's layout and its
`build-depends`, read by the `.cabal` reader and by `cabal.project` and `cabal.project.freeze`
alike, so below both."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Iterator


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


__all__ = ["GHC_PACKAGES", "CabalDeps", "CabalLayout", "CabalNode"]
