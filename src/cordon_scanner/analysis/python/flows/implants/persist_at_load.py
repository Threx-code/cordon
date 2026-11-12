"""A persistence location written by code that runs when the file is loaded.

`py_persist.py` finds the lines that write a shell profile, a crontab, a service, an agent, a Run key
or the like (a literal naming one that reaches a write or a process). Whether that write happens when
the file is imported is another question: a scheduler library defines `enable()` in its `__init__.py`
and nothing runs it. A write counts here only when it is at module level, or in a function the module
level calls (through any number of the file's own helpers). `if __name__ == "__main__":` is not
loading, and a class body is: it runs when the class is defined.

`lines` returns the line of each such write.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

from cordon_scanner.analysis.python.py_persist import PythonPersistence
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class PersistAtLoad:
    """The persistence writes that run at load, in one syntax tree."""

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        written = PythonPersistence.written_lines(tree)
        if not written or not isinstance(tree, ast.Module):
            return []
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in PythonSyntax.walked_of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.setdefault(node.name, node)
        loaded = cls._loaded_names(tree, functions)
        out: list[int] = []
        spans = [(fn.lineno, fn.end_lineno or fn.lineno, name) for name, fn in functions.items()]
        for line in sorted(written):
            inside = [name for start, end, name in spans if start <= line <= end]
            if not inside:
                if not cls._under_main_guard(tree, line):
                    out.append(line)
            elif all(name in loaded for name in inside):
                out.append(line)
        return out

    @classmethod
    def load_time_lines(cls, tree: ast.AST) -> frozenset[int]:
        """The lines of every call that runs when the file is loaded: those at module level (and in
        a class body), and every line of a function the module level calls, through the file's own
        helpers. Not the main guard, not a function nothing calls."""
        if not isinstance(tree, ast.Module):
            return frozenset()
        functions: dict[str, ast.AST] = {}
        for node in PythonSyntax.walked_of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.setdefault(node.name, node)
        lines = {c.lineno for c in cls._top_level_calls(tree.body)}
        for name in cls._loaded_names(tree, functions):
            fn = functions[name]
            lines.update(range(fn.lineno, (fn.end_lineno or fn.lineno) + 1))  # type: ignore[attr-defined]
        return frozenset(lines)

    @classmethod
    def _top_level_calls(cls, body: list[ast.stmt]) -> list[ast.Call]:
        """The calls the statements make when they run, leaving out function bodies and the main guard."""
        calls: list[ast.Call] = []
        stack: list[ast.AST] = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                continue
            if isinstance(node, ast.If) and cls._is_main_guard(node):
                continue
            if isinstance(node, ast.Call):
                calls.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return calls

    @classmethod
    def _loaded_names(cls, tree: ast.Module, functions: Mapping[str, ast.AST]) -> set[str]:
        loaded: set[str] = set()
        pending = [cls._called(c) for c in cls._top_level_calls(tree.body)]
        while pending:
            name = pending.pop()
            if name is None or name in loaded or name not in functions:
                continue
            loaded.add(name)
            fn = functions[name]
            pending.extend(cls._called(c) for c in cls._top_level_calls(fn.body))  # type: ignore[attr-defined]
        return loaded

    @staticmethod
    def _called(call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    @staticmethod
    def _is_main_guard(node: ast.If) -> bool:
        return "__main__" in ast.dump(node.test)

    @classmethod
    def _under_main_guard(cls, tree: ast.Module, line: int) -> bool:
        return any(
            isinstance(n, ast.If)
            and cls._is_main_guard(n)
            and n.lineno <= line <= (n.end_lineno or n.lineno)
            for n in tree.body
        )


__all__ = ["PersistAtLoad"]
