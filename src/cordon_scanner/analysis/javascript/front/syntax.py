"""The syntax tree of Cordon's JavaScript front end: a node, its type, its span, its children.

One node class, not one per syntax form: a node is its `type` (an ESTree name -- `CallExpression`,
`ImportDeclaration`), its source span, and its children by field name. Nothing holds source text:
a node points into the text, and `text(node)` slices it when asked, so a tree's memory is its node
count. Walking is iterative (`Syntax.walk`), so no tree is too deep to visit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


class Node:
    """A syntax node: `type`, `start` and `end` (character offsets), and `fields` by name."""

    __slots__ = ("end", "fields", "start", "type")

    def __init__(self, type: str, start: int, end: int, **fields: Any) -> None:
        self.type, self.start, self.end, self.fields = type, start, end, fields

    def __getitem__(self, name: str) -> Any:
        return self.fields.get(name)

    def __repr__(self) -> str:
        return f"Node({self.type}, {self.start}-{self.end})"


class Syntax:
    """Reading a tree."""

    @staticmethod
    def children(node: Node) -> Iterator[Node]:
        for value in node.fields.values():
            if isinstance(value, Node):
                yield value
            elif isinstance(value, list):
                yield from (item for item in value if isinstance(item, Node))

    @staticmethod
    def walk(root: Node) -> Iterator[Node]:
        """Every node under `root`, in source order, `root` first; by an explicit stack."""
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(list(Syntax.children(node))))


__all__ = ["Node", "Syntax"]
