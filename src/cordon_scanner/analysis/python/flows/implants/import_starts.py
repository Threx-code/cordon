"""A program started and left running when a package is imported.

Importing a library loads code; it has no reason to start a program and walk away. A library that
asks the machine something at import (`gdal-config`, `nvcc`, `xcrun`) runs it and reads the answer,
and one that clears the screen waits for it. A package that starts a program with `Popen` and
does not read what it prints (no `stdout=` or `stderr=` pipe) has launched something that outlives
the import: `subprocess.Popen(["<program>", ...])` in `__init__.py`, with or without a variable
for the handle.

`lines` returns the line of each such statement that runs when the file is loaded: at module level,
in a class body, or in a function the module level calls. The interpreter, pip and the version
control tools, and the terminal's `clear`, are not programs a package brings.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.flows.implants.persist_at_load import PersistAtLoad


class ImportStarts:
    """The fire-and-forget starts at load in one syntax tree."""

    OWN: ClassVar[tuple[str, ...]] = ("python", "pip", "git", "hg", "svn", "clear", "cls", "sys.executable")

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        loaded = PersistAtLoad.load_time_lines(tree)
        out: list[int] = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Expr | ast.Assign) and isinstance(node.value, ast.Call) and node.lineno in loaded):
                continue
            call = node.value
            if any(k.arg in ("stdout", "stderr") for k in call.keywords):
                continue  # its output is read: the program is asked a question
            name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            argv = call.args[0] if call.args else None
            if name != "Popen" or not isinstance(argv, ast.List | ast.Tuple) or not argv.elts:
                continue
            first = argv.elts[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            program = first.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if not program.startswith(cls.OWN):
                out.append(node.lineno)
        return sorted(out)


__all__ = ["ImportStarts"]
