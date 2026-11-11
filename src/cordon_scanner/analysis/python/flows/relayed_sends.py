"""What a caller hands a class, sent on to a destination the class keeps hidden (dependency chain).

snapshot-photo 0.0.3 and snapshot_date 1.0.3 each define `Dateformat(day, month, year)`: `__init__`
stores the arguments on `self`, and `get_date()` posts `json.dumps({...self.day...})` to
`self.endp[::-1] + self.year`, a destination written reversed on an attribute. Their callers hand
their cloud keys over as "day" and "month" (credential_python_sdk, acloud-client). The class is a
relay: whatever it is given goes to a host its source does not show.

`relayed to hidden: <sink> dest=decoded`: a method of a class makes a request whose destination is
hidden (`HiddenDestinations._hidden`, which folds attribute-held constants) and whose body is built
from `self.<attr>`, where `__init__` stores a constructor parameter in that attribute.
"""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.flows.swept_sends import SweptSends
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.scoped_taint import BindingForms
from cordon_scanner.foundation.capabilities import Capability


class RelayedSends(SweptSends):
    """`_relayed_to_hidden` and what it needs."""

    def _relayed_to_hidden(self, tree: ast.AST) -> None:
        hidden = self._hidden(tree)
        for cls in PythonSyntax.of(tree, ast.ClassDef):
            stored = self._constructor_attributes(cls)
            if not stored:
                continue
            for method in cls.body:
                if not isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                for sink, destination, body in self._request_parts(method):
                    if hidden(destination) and self._body_reads_stored(method, body, stored):
                        self._record(
                            Capability.EGRESS, method, f"relayed to hidden: {sink} dest=decoded"
                        )
                        break

    @staticmethod
    def _constructor_attributes(cls: ast.ClassDef) -> set[str]:
        """Attributes `__init__` stores a constructor parameter (or a piece of one) in."""
        init = next(
            (
                f
                for f in cls.body
                if isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef) and f.name == "__init__"
            ),
            None,
        )
        if init is None:
            return set()
        params = {a.arg for a in (*init.args.posonlyargs, *init.args.args, *init.args.kwonlyargs)}
        params.discard("self")
        stored: set[str] = set()
        for node in PythonSyntax.within(init, ast.Assign):
            if not any(
                isinstance(n, ast.Name) and n.id in params for n in PythonSyntax.nodes(node.value)
            ):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                ):
                    stored.add(target.attr)
        return stored

    @staticmethod
    def _body_reads_stored(method: ast.AST, body: list[ast.AST], stored: set[str]) -> bool:
        """Whether the body reads one of `stored` (`self.day`), directly or through the method's
        own bindings (`json_data = json.dumps({"d": self.day})`)."""

        def reads(node: ast.AST) -> bool:
            return any(
                isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)
                and n.value.id == "self"
                and n.attr in stored
                for n in PythonSyntax.nodes(node)
            )

        carrying: set[str] = set()
        for _ in range(4):
            for node in PythonSyntax.within(method, ast.Assign):
                if reads(node.value) or any(
                    isinstance(n, ast.Name) and n.id in carrying
                    for n in PythonSyntax.nodes(node.value)
                ):
                    for target in node.targets:
                        carrying.update(BindingForms.names(target))
        return any(
            reads(expr)
            or any(isinstance(n, ast.Name) and n.id in carrying for n in PythonSyntax.nodes(expr))
            for expr in body
        )


__all__ = ["RelayedSends"]
