"""A program started and left running when a package is imported.

Importing a library loads code; it has no reason to start a program and walk away. A library that
asks the machine something at import (`gdal-config`, `nvcc`, `xcrun`) runs it and reads the answer,
and one that clears the screen waits for it. A package that starts a program with `Popen`
at import, with a literal argument list, has launched something that outlives the import:
`subprocess.Popen(["<program>", ...])` in `__init__.py`, with or without a variable for the handle,
and whether or not it reads what the program prints (a launcher that pipes its output and loops over
it is the case in point).

`lines` returns the line of each such statement that runs when the file is loaded: at module level,
in a class body, or in a function the module level calls. The interpreter, pip, the version control tools, the terminal's `clear` and the privilege and
permission tools are not programs a package brings.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.flows.implants.persist_at_load import PersistAtLoad
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class ImportStarts:
    """The fire-and-forget starts at load in one syntax tree."""

    OWN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:python[0-9.]*|pip[0-9.]*|git|hg|svn|clear|cls|sudo|dzdo|doas|su|chown|chmod|chgrp)(?:\.exe)?"
    )

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        loaded = PersistAtLoad.load_time_lines(tree)
        out: list[int] = []
        for node in PythonSyntax.walked(tree):
            if not (
                isinstance(node, ast.Expr | ast.Assign)
                and isinstance(node.value, ast.Call)
                and node.lineno in loaded
            ):
                continue
            call = node.value
            name = (
                call.func.attr
                if isinstance(call.func, ast.Attribute)
                else getattr(call.func, "id", "")
            )
            argv = call.args[0] if call.args else None
            if name != "Popen" or not isinstance(argv, ast.List | ast.Tuple) or not argv.elts:
                continue
            first = argv.elts[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            program = first.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if cls.OWN.fullmatch(program) is None:
                out.append(node.lineno)
        return sorted(out)


__all__ = ["ImportStarts"]
