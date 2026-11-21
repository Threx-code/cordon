"""Files swept from the disk, sent to a destination the file keeps hidden (group E2).

graphicsctxr 1.0.3 walks every drive or the home directory, reads each file it keeps, and hands the
text to `emit_glyph(name, text, base_url=...)`, which posts it to a URL `decode_uri_glyph()` decodes
from a constant. The hidden destination is already a fact (`HiddenDestinations`); a sweep alone is
what backup and search tools do, and a hidden destination alone is 11 of 1,063 benign packages.
Together, contents of swept files in the body of a request whose destination the file hides, they
are a stealer's whole act (4 of 1,063 benign packages hold both anywhere at all, before this flow).

The join is through one same-file helper: the helper's parameters that reach a hidden request's
body, and each call of it passing, at one of those positions, a file read whose path a walker
yields. Parsed, never executed.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.flows.hidden_destinations import HiddenDestinations
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.scoped_taint import BindingForms
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable


class SweptSends(HiddenDestinations):
    """`_swept_sends` and what it needs."""

    #: Calls that walk a tree of files.
    WALKERS: ClassVar[frozenset[str]] = frozenset(
        {"os.walk", "os.scandir", "os.listdir", "glob.glob", "glob.iglob"}
    )
    WALK_METHODS: ClassVar[frozenset[str]] = frozenset({"rglob", "glob", "walk", "iterdir"})
    READS: ClassVar[frozenset[str]] = frozenset({"read_text", "read_bytes", "read"})
    #: Keywords a request's body travels in.
    BODY_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"data", "json", "files", "content", "body"}
    )

    def _swept_sends(self, tree: ast.AST) -> None:
        """`swept files sent: <sink> dest=decoded`."""
        self.__dict__["_swept_tree"] = tree
        hidden = self._hidden(tree)
        functions = {
            f.name: f for f in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        }
        walkers = self._walking_functions(functions)
        for function in functions.values():
            ordered = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
            for sink, destination, body in self._request_parts(function):
                carried = self._parameters_reaching(function, body, ordered)
                if not carried:
                    continue
                hidden_here = hidden(destination)
                routed = self._parameters_reaching(function, [destination], ordered)
                for call in PythonSyntax.of(tree, ast.Call):
                    if not (isinstance(call.func, ast.Name) and call.func.id == function.name):
                        continue
                    scope = self._scope_of(tree, call, functions)
                    hides = hidden_here or any(
                        hidden(arg) or self._names_hidden(arg, scope, hidden)
                        for arg in self._passed(call, routed, ordered)
                    )
                    if hides and any(
                        self._swept_read(arg, scope, walkers)
                        for arg in self._passed(call, carried, ordered)
                    ):
                        self._record(
                            Capability.EGRESS, call, f"swept files sent: {sink} dest=decoded"
                        )

    @staticmethod
    def _passed(call: ast.Call, params: set[str], ordered: list[str]) -> list[ast.AST]:
        """The arguments a call passes for these parameters, by position or keyword."""
        positions = {ordered.index(p) for p in params if p in ordered}
        passed: list[ast.AST] = [a for i, a in enumerate(call.args) if i in positions]
        passed += [k.value for k in call.keywords if k.arg in params]
        return passed

    @staticmethod
    def _names_hidden(arg: ast.AST, scope: ast.AST, hidden: Callable[..., bool]) -> bool:
        """A name the calling scope binds to a hidden value (`base_url = decode_url()`)."""
        names = {n.id for n in PythonSyntax.nodes(arg) if isinstance(n, ast.Name)}
        return any(
            hidden(node.value)
            for node in PythonSyntax.within(scope, ast.Assign)
            for t in node.targets
            if set(BindingForms.names(t)) & names
        )

    def _request_parts(self, function: ast.AST) -> list[tuple[str, ast.AST, list[ast.AST]]]:
        """(sink, destination, body expressions) of each request the function makes."""
        found: list[tuple[str, ast.AST, list[ast.AST]]] = []
        for call in PythonSyntax.within(function, ast.Call):
            resolved = self._resolve_callee(call)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                continue
            destination = self._destination_of(resolved[1])
            if destination is None:
                continue
            body = [
                *call.args[1:],
                *(k.value for k in call.keywords if k.arg in self.BODY_KEYWORDS),
            ]
            # `req = Request(url, data=payload)` then `urlopen(req)`: the request object holds
            # the destination and the body.
            built = self._request_object(function, destination)
            if built is not None:
                destination = self._destination_of(built) or destination
                body += [
                    *built.args[1:],
                    *(k.value for k in built.keywords if k.arg in self.BODY_KEYWORDS),
                ]
            found.append((resolved[0], destination, body))
        return found

    #: Constructors of a request object a send then makes.
    REQUEST_OBJECTS: ClassVar[frozenset[str]] = frozenset(
        {"urllib.request.Request", "requests.Request", "httpx.Request"}
    )

    def _request_object(self, function: ast.AST, destination: ast.AST) -> ast.Call | None:
        """The `Request(...)` a name passed to a send is bound to, in the same function."""
        if not isinstance(destination, ast.Name):
            return None
        for node in PythonSyntax.within(function, ast.Assign):
            if (
                isinstance(node.value, ast.Call)
                and (self._dotted(node.value.func) or "") in self.REQUEST_OBJECTS
                and any(destination.id in BindingForms.names(t) for t in node.targets)
            ):
                return node.value
        return None

    @staticmethod
    def _parameters_reaching(function: ast.AST, body: list[ast.AST], params: list[str]) -> set[str]:
        """The parameters the body is built from, through the function's own bindings."""
        carries: dict[str, set[str]] = {p: {p} for p in params}
        for _ in range(4):
            for node in PythonSyntax.within(function, ast.Assign):
                sources = {
                    q
                    for n in PythonSyntax.nodes(node.value)
                    if isinstance(n, ast.Name)
                    for q in carries.get(n.id, ())
                }
                if sources:
                    for t in node.targets:
                        for name in BindingForms.names(t):
                            carries.setdefault(name, set()).update(sources)
        return {
            p
            for expr in body
            for n in PythonSyntax.nodes(expr)
            if isinstance(n, ast.Name)
            for p in carries.get(n.id, ())
        }

    def _walking_functions(self, functions: dict[str, ast.AST]) -> set[str]:
        """The file's functions that walk a tree of files (a sweep's generator)."""
        return {name for name, f in functions.items() if self._walks(f)}

    def _walks(self, node: ast.AST) -> bool:
        for call in PythonSyntax.within(node, ast.Call):
            if (self._dotted(call.func) or "") in self.WALKERS:
                return True
            if isinstance(call.func, ast.Attribute) and call.func.attr in self.WALK_METHODS:
                return True
        return False

    @staticmethod
    def _scope_of(tree: ast.AST, call: ast.AST, functions: dict[str, ast.AST]) -> ast.AST:
        line = getattr(call, "lineno", 0)
        holding = [
            f
            for f in functions.values()
            if f.lineno <= line <= (getattr(f, "end_lineno", None) or f.lineno)  # type: ignore[attr-defined]
        ]
        return min(holding, key=lambda f: f.end_lineno - f.lineno) if holding else tree  # type: ignore[attr-defined]

    def _swept_read(self, arg: ast.AST, scope: ast.AST, walkers: set[str]) -> bool:
        """Whether `arg` holds a file read whose path a walker yields, in this scope."""
        read_names = self._read_names(scope)
        return any(
            (isinstance(n, ast.Name) and n.id in read_names)
            or (isinstance(n, ast.Call) and self._is_swept_read_call(n, scope, walkers))
            for n in PythonSyntax.nodes(arg)
        )

    def _read_names(self, scope: ast.AST) -> set[str]:
        names: set[str] = set()
        walkers = self._walking_functions(
            {f.name: f for f in PythonSyntax.of(scope, ast.FunctionDef, ast.AsyncFunctionDef)}
        )
        for node in PythonSyntax.within(scope, ast.Assign):
            if any(
                isinstance(n, ast.Call) and self._is_swept_read_call(n, scope, walkers)
                for n in PythonSyntax.nodes(node.value)
            ):
                for t in node.targets:
                    names.update(BindingForms.names(t))
        return names

    def _is_swept_read_call(self, call: ast.Call, scope: ast.AST, walkers: set[str]) -> bool:
        """`path.read_text()` / `open(path).read()` where `path` is a loop variable over a walk."""
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr in self.READS):
            return False
        receiver = func.value
        if (
            isinstance(receiver, ast.Call)
            and self._dotted(receiver.func) == "open"
            and receiver.args
        ):
            receiver = receiver.args[0]
        names = {n.id for n in PythonSyntax.nodes(receiver) if isinstance(n, ast.Name)}
        for loop in PythonSyntax.within(scope, ast.For):
            targets = set(BindingForms.names(loop.target))
            if not targets & names:
                continue
            iterated = loop.iter
            if self._walks(iterated):
                return True
            called = {
                c.func.id
                for c in PythonSyntax.nodes(iterated)
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            }
            if called & walkers or called & self._module_walkers():
                return True
        return False

    def _module_walkers(self) -> set[str]:
        tree = self.__dict__.get("_swept_tree")
        if tree is None:
            return set()
        return self._walking_functions(
            {f.name: f for f in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)}
        )


__all__ = ["SweptSends"]
