"""What a caller hands a class, sent on to a destination the class keeps hidden (dependency chain).

snapshot-photo 0.0.3 and snapshot_date 1.0.3 each define `Dateformat(day, month, year)`: `__init__`
stores the arguments on `self`, and `get_date()` posts `json.dumps({...self.day...})` to
`self.endp[::-1] + self.year`, a destination written reversed on an attribute. Their callers hand
their cloud keys over as "day" and "month" (credential_python_sdk, acloud-client). The class is a
relay: whatever it is given goes to a host its source does not show.

`relayed to hidden: <sink> dest=decoded`: a method of a class makes a request whose destination is
hidden (`HiddenDestinations._hidden`, which folds attribute-held constants) and whose body is built
from `self.<attr>`, where `__init__` stores a constructor parameter in that attribute. A
destination whose head writes the whole host down (`"https://api.github.com/repos/{}".format(...)`,
`"https://host/" + path[::-1]`, a signed query on a named host), or takes it plain from a
parameter or another object (`self.user.url.format(...)`), hides no destination (ailever,
pygitconnect, a TikTok signing client: 3 of 16,274 before this). Any other head still counts: a
hidden value, a parameter, `"" + host`, `"{}{}".format(host, path)` or `"https://{}/".format(host)`.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from typing import Any, ClassVar

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
                    if (
                        hidden(destination)
                        and self._head_hides_host(hidden, cls, method, destination)
                        and self._body_reads_stored(method, body, stored)
                    ):
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

    #: Characters a host label is made of; the scheme also allows `+ . -`.
    _LABEL: ClassVar[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

    @classmethod
    def _host_written(cls, text: str) -> bool:
        """Whether a literal names the whole host and ends it (`https://a.b/`, `:`, `?`, `#`):
        the destination is in plain sight. String operations only, no pattern."""
        scheme, sep, rest = text.lower().partition("://")
        if not sep or not scheme[:1].isalpha() or not set(scheme) <= cls._LABEL | {"+", "."}:
            return False
        end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=-1)
        if end < 0:
            return False
        host, _, port = rest[:end].partition(":")
        labels = host.split(".")
        return (
            len(labels) > 1
            and all(label and set(label) <= cls._LABEL for label in labels)
            and (not port or port.isdigit())
        )

    def _head_hides_host(
        self,
        hidden: Callable[..., bool],
        cls: ast.ClassDef,
        method: ast.AST,
        destination: ast.AST,
    ) -> bool:
        """Whether the host comes from the hidden part: the head is itself hidden, or is a literal
        that leaves the host to what follows it (`""`, `"{}{}"`, `"https://{}/"`). A head the file
        writes down, or takes plain from a parameter or another object, names the host itself."""
        head = self._destination_head(cls, method, destination)
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return not self._host_written(head.value)
        return bool(hidden(head))

    @staticmethod
    def _binding_key(node: ast.AST) -> str | None:
        """`x` for a name, `self.x` for an attribute of self; None otherwise."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"self.{node.attr}" if node.value.id == "self" else None
        return None

    #: How each kind of expression steps toward its leftmost piece.
    _STEPS: ClassVar[dict[type, Callable[[Any], ast.AST | None]]] = {
        ast.BinOp: lambda n: n.left,
        ast.JoinedStr: lambda n: n.values[0] if n.values else None,
        ast.FormattedValue: lambda n: n.value,
    }

    @staticmethod
    def _leftmost(node: ast.AST) -> ast.AST | None:
        """One step toward a destination's head: the left of `+`, an f-string's first piece, a
        formatted value's expression, a `.format()` call's template; None when there is none."""
        step = RelayedSends._STEPS.get(type(node))
        if step is not None:
            return step(node)
        func = getattr(node, "func", None)
        if isinstance(node, ast.Call) and isinstance(func, ast.Attribute) and func.attr == "format":
            return func.value
        return None

    @classmethod
    def _destination_head(
        cls, owner: ast.ClassDef, method: ast.AST, destination: ast.AST
    ) -> ast.AST:
        """The leftmost piece of a destination, the one that names the host: through `+`, f-strings
        and `.format()` templates, and through a local or `self.<attr>` binding to its value."""
        bound: dict[str, ast.AST] = {}
        for scope, attributes in ((owner, True), (method, False)):
            for node in PythonSyntax.within(scope, ast.Assign):
                for target in node.targets:
                    key = cls._binding_key(target)
                    if key is not None and key.startswith("self.") is attributes:
                        bound.setdefault(key, node.value)
        head = destination
        for _ in range(8):
            key = cls._binding_key(head)
            following = bound.pop(key) if key in bound else cls._leftmost(head)
            if following is None:
                break
            head = following
        return head

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
