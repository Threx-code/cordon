"""The syntax tree of Cordon's JavaScript front end: a node, its type, its span, its children.

One node class, not one per syntax form: a node is its `type` (an ESTree name -- `CallExpression`,
`ImportDeclaration`), its source span, and its children by field name. Nothing holds source text:
a node points into the text, and `text(node)` slices it when asked, so a tree's memory is its node
count. Walking is iterative (`Syntax.walk`), so no tree is too deep to visit.

A node keeps its fields as a tuple of values beside its shape, the tuple of their names, which one
shape shares with every node built the same way. A dictionary per node was half the tree: 337 of
635 MB on a 10 MB bundle of 1.85 million nodes (review 98, D4).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Iterator


class Node:
    """A syntax node: `type`, `start` and `end` (character offsets), and its fields by name
    (`node["callee"]`; `fields` gives them as a dictionary)."""

    __slots__ = ("_names", "_values", "end", "start", "type")

    #: Each distinct tuple of field names, kept once: the grammar builds a few dozen shapes.
    SHAPES: ClassVar[dict[tuple[str, ...], tuple[str, ...]]] = {}

    def __init__(self, type: str, start: int, end: int, **fields: Any) -> None:
        self.type, self.start, self.end = type, start, end
        names = tuple(fields)
        self._names = Node.SHAPES.setdefault(names, names)
        self._values = tuple(fields.values())

    def __getitem__(self, name: str) -> Any:
        names = self._names
        return self._values[names.index(name)] if name in names else None

    @property
    def fields(self) -> dict[str, Any]:
        """The fields by name, in the order they were given."""
        return dict(zip(self._names, self._values, strict=True))

    def __repr__(self) -> str:
        return f"Node({self.type}, {self.start}-{self.end})"


class Syntax:
    """Reading a tree."""

    @staticmethod
    def children(node: Node) -> Iterator[Node]:
        for value in node._values:
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
