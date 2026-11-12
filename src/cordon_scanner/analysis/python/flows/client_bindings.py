"""Names bound to an HTTP client object: `with … as client` and a local factory returning one
(group A (a)). Moved out of `PythonAnalyzer` whole (its method limit)."""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.flows.http_clients import HTTP_CLIENTS
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class ClientBindings(AnalyzerCore):
    """The client half of name binding."""

    def _bind_with(self, node: ast.With | ast.AsyncWith) -> None:
        """`with httpx.Client() as client:`: the name is the client (`HTTP_CLIENTS`)."""
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                client = self._dotted(item.context_expr)
                if client in HTTP_CLIENTS:
                    self._bindings[item.optional_vars.id] = client

    def _bind_client_factories(self, tree: ast.AST) -> None:
        """A function of this file that returns an HTTP client is that client when called
        (`def _build_retry_session(): s = requests.Session(); ...; return s`), and so is what its
        call is assigned to (`self._session = _build_retry_session()`). Bounded rounds: a factory
        may return another factory's client."""
        functions = PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        for _ in range(4):
            grew = False
            for function in functions:
                if self._bindings.get(function.name) in HTTP_CLIENTS:
                    continue
                for ret in PythonSyntax.within(function, ast.Return):
                    client = self._dotted(ret.value) if ret.value is not None else None
                    if client in HTTP_CLIENTS:
                        self._bindings[function.name] = client
                        grew = True
                        break
            for node in PythonSyntax.of(tree, ast.Assign):
                if len(node.targets) != 1 or not isinstance(node.value, ast.Call):
                    continue
                client = self._dotted(node.value)
                if client not in HTTP_CLIENTS:
                    continue
                target = node.targets[0]
                if isinstance(target, ast.Name) and self._bindings.get(target.id) != client:
                    self._bindings[target.id] = client
                    grew = True
                elif (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in ("self", "cls")
                ):
                    key = f"{target.value.id}.{target.attr}"
                    if self._attribute_bindings.get(key) != client:
                        self._attribute_bindings[key] = client
                        grew = True
            if not grew:
                return


__all__ = ["ClientBindings"]
