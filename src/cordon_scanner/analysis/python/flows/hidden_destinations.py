"""A request whose destination the file kept hidden (group A (a)): decoded, reversed or built
from chr() codes, and the `hidden request` fact. Moved out of `DataFlows` whole (its method and
module limits)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES, PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable


class HiddenDestinations(AnalyzerCore):
    """`_hidden`, `_dest` and `_hidden_requests`."""

    #: The keyword arguments a request names its destination by.
    _URL_KEYWORDS: ClassVar[tuple[str, ...]] = ("url", "uri", "host", "address", "endpoint")

    def _hidden(self, tree: ast.AST) -> Callable[..., bool]:
        """Whether an expression holds a value the file kept hidden: decoded (a DECODE or
        DECOMPRESS primitive), reversed (`s[::-1]`, `reversed(s)`), or built from `chr()` codes,
        carried through names, returns and `self.x` (`PythonFacts.carried`). Once per tree."""
        cached: tuple[ast.AST, Callable[..., bool]] | None = self.__dict__.get("_hidden_cache")
        if cached is not None and cached[0] is tree:
            return cached[1]

        def is_hidden(node: ast.AST) -> bool:
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
                step = node.slice.step
                return (
                    isinstance(step, ast.UnaryOp)
                    and isinstance(step.op, ast.USub)
                    and isinstance(step.operand, ast.Constant)
                    and step.operand.value == 1
                )
            if not isinstance(node, ast.Call):
                return False
            if isinstance(node.func, ast.Name) and node.func.id in ("chr", "reversed"):
                return True
            resolved = self._resolve_callee(node)
            return resolved is not None and PRIMITIVES.get(resolved[0]) in (
                Capability.DECODE,
                Capability.DECOMPRESS,
            )

        holds = PythonFacts.carried(tree, is_hidden, ast.Subscript)
        self.__dict__["_hidden_cache"] = (tree, holds)
        return holds

    def _destination_of(self, call: ast.Call) -> ast.AST | None:
        if call.args:
            return call.args[0]
        return next((k.value for k in call.keywords if k.arg in self._URL_KEYWORDS), None)

    def _dest(self, tree: ast.AST, call: ast.Call) -> str:
        """` dest=decoded` when the request's destination is a hidden value (group A (a)); the
        detail otherwise unchanged."""
        destination = self._destination_of(call)
        return (
            " dest=decoded" if destination is not None and self._hidden(tree)(destination) else ""
        )

    def _hidden_requests(self, tree: ast.AST) -> None:
        """`hidden request: <sink> dest=decoded`: a request whose destination the file kept hidden,
        whatever it sends (snapshot-photo 0.0.3: `self.endp[::-1] + year`). A fact for grading;
        what it weighs alone is the rule's to decide, from its benign count."""
        hidden = self._hidden(tree)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            destination = self._destination_of(resolved[1])
            if destination is not None and hidden(destination):
                self._record(Capability.EGRESS, node, f"hidden request: {resolved[0]} dest=decoded")


__all__ = ["HiddenDestinations"]
