"""A container a statement fills with a value (group A (a)): what `PythonFacts.carried` follows
through `box[k] = v`, `box += v` and `box.append(v)`. Moved out of `pyfacts.py` (its length limit)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Callable


class Containers:
    #: Methods that put their argument into their receiver.
    FILLS: ClassVar[frozenset[str]] = frozenset(
        {"append", "extend", "update", "add", "insert", "setdefault", "appendleft", "write",
         "writelines", "writestr"}
    )  # fmt: skip

    @staticmethod
    def filled_by(node: ast.AST, holds: Callable[..., bool]) -> list[ast.AST]:
        """The container a statement puts a held value into: `box[k] = v` (item assignment),
        `box += v`, `box.append(v)` and the other `FILLS`. A dict or list built up a key at a time
        and sent whole is how a collector is written as often as a literal is."""
        if isinstance(node, ast.Assign) and holds(node.value):
            return [t.value for t in node.targets if isinstance(t, ast.Subscript)]
        if isinstance(node, ast.AugAssign) and holds(node.value):
            target = node.target
            return [target.value if isinstance(target, ast.Subscript) else target]
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in Containers.FILLS
            and any(holds(a) for a in [*node.args, *(k.value for k in node.keywords)])
        ):
            return [node.func.value]
        return []


__all__ = ["Containers"]
