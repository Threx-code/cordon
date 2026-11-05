"""A field two engines declare under one name with different types (`values.Dual`), read in one shape
per rule: the shape the operand's type picks, else the reference's, with a note on the rule's load result
so the choice is never silent. The builder (`rule_engine.build`) calls these where a dual field meets a
comparison, a function's parameter, `matches` or `defined`."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.binary.modules.values import Dual, Scalar
from cordon_scanner.detect.binary.rule_engine.syntax import Field, Literal, Node, Path, RuleDef

HEXDIGITS = b"0123456789abcdefABCDEF"


class Shapes:
    """Which shape a rule reads a dual field in, and the reading."""

    @staticmethod
    def spell(node: Node) -> str:
        """A path as the rule wrote it, for a note."""
        if isinstance(node, Path):
            return ".".join([node.root, *(s.name for s in node.steps if isinstance(s, Field))])
        return type(node).__name__.lower()

    @staticmethod
    def decide(kind: Any, other: Any, other_node: Node) -> int | None:
        """Which shape of a Dual the operand on the other side picks: the one shape of the operand's
        type; between two text shapes, a literal of forty hex digits picks the second, any other text
        literal the first, and an operand reached through a companion name picks the second. None
        when nothing in the rule decides."""
        if not isinstance(kind, Dual) or not isinstance(other, Scalar):
            return None
        index = kind.index_of(other)
        if index is not None:
            return index
        if isinstance(other_node, Literal) and isinstance(other_node.value, bytes):
            v = other_node.value
            return 1 if len(v) == 40 and all(c in HEXDIGITS for c in v) else 0
        if isinstance(other_node, Path) and any(
            isinstance(step, Field) and step.name in kind.companions for step in other_node.steps
        ):
            return 1
        return None

    @staticmethod
    def settle(
        rule: RuleDef, kind: Any, fn: Callable[[Any], Any], index: int | None, node: Node
    ) -> tuple[Any, Callable[[Any], Any]]:
        """A field with two shapes read in one: `index` picks it; None means nothing in the rule
        decided, so the first (the reference's) is read and the rule's load result says so."""
        if not isinstance(kind, Dual):
            return kind, fn
        if index is None:
            index = 0
            rule.notes.append(
                f"{Shapes.spell(node)} has two shapes and nothing in the rule decides: "
                f"read as {kind.labels[0]}, not {kind.labels[1]}"
            )
        chosen = index

        def pick(f: Any) -> Any:
            v = fn(f)
            return None if v is None else v[chosen]

        return kind.shape(chosen), pick


__all__ = ["Shapes"]
