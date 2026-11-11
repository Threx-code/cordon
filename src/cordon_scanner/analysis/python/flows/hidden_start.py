"""A process started with its window hidden (group D: fetch_data_api_syncapi 0.1.1 downloads an EXE to the
temp directory and starts it with `STARTUPINFO.wShowWindow = 0`).

A downloader that runs what it fetched is a dropper; one that also hides the window it starts is
concealing it from the person at the machine. Hidden is read from the start call itself
(`creationflags=` a literal, or naming CREATE_NO_WINDOW / DETACHED_PROCESS / SW_HIDE) or from the
`startupinfo=` it passes, when the function that makes the call sets `wShowWindow` or
`STARTF_USESHOWWINDOW` (the STARTUPINFO way to hide a window).
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class HiddenStart:
    """Whether a process start hides its window."""

    #: Flags and fields whose only use on a process start is to keep its window from showing.
    HIDING: ClassVar[frozenset[str]] = frozenset(
        {"CREATE_NO_WINDOW", "DETACHED_PROCESS", "SW_HIDE", "wShowWindow", "STARTF_USESHOWWINDOW"}
    )

    @classmethod
    def of(cls, tree: ast.AST, call: ast.Call) -> bool:
        """`call` (a process start) hides its window."""
        for keyword in call.keywords:
            if keyword.arg == "creationflags" and (
                isinstance(keyword.value, ast.Constant) or cls._names_hiding(keyword.value)
            ):
                return True
            if keyword.arg == "startupinfo" and cls._scope_hides(tree, call):
                return True
        return False

    @classmethod
    def _names_hiding(cls, node: ast.AST) -> bool:
        return any(
            (isinstance(n, ast.Attribute) and n.attr in cls.HIDING)
            or (isinstance(n, ast.Name) and n.id in cls.HIDING)
            for n in ast.walk(node)
        )

    @classmethod
    def _scope_hides(cls, tree: ast.AST, call: ast.Call) -> bool:
        """The innermost function holding `call` (or the module) sets a window-hiding field."""
        line = getattr(call, "lineno", 0)
        scope: ast.AST = tree
        for function in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            start, end = function.lineno, getattr(function, "end_lineno", function.lineno)
            if start <= line <= end and (scope is tree or start >= getattr(scope, "lineno", 0)):
                scope = function
        return cls._names_hiding(scope)


__all__ = ["HiddenStart"]
