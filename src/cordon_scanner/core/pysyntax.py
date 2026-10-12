"""Python source parsed as data.

`ast.parse` warns about the source it reads: `"\\h"`, an invalid escape in a scanned file, is a
`SyntaxWarning` (a `DeprecationWarning` before 3.12), written to the scanner's own stderr once per
literal. Scanning stable-diffusion printed seven of them into a CI log, which reads as the
scanner failing. A scanned file's escapes are its author's business; the warnings are not ours to
print, so every parse of untrusted source goes through here.
"""

from __future__ import annotations

import ast
import functools
import warnings
from typing import Any


class PythonSyntax:
    @staticmethod
    def parse(source: str | bytes, filename: str = "<unknown>", mode: str = "exec") -> Any:
        """`ast.parse`, without the warnings it raises about the source. Raises what it raises:
        a `SyntaxError` (or `ValueError` for a NUL byte) is still the caller's to handle."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            return ast.parse(source, filename=filename, mode=mode)

    @staticmethod
    @functools.lru_cache(maxsize=4)
    def shared(source: str | bytes) -> Any:
        """One parse of `source` shared by every reader that does not change the tree: the Python
        analyser asks four questions of each file, and parsing it four times was most of a large
        package's scan. A reader that annotates or rewrites nodes must call `parse`."""
        return PythonSyntax.parse(source)

    @staticmethod
    def nodes(tree: ast.AST) -> list[ast.AST]:
        """`list(ast.walk(tree))`, computed once per tree: the same nodes in the same order, for a
        reader that walks the same tree many times."""
        cached = tree.__dict__.get("_cordon_nodes")
        if cached is None:
            cached = list(ast.walk(tree))
            tree.__dict__["_cordon_nodes"] = cached
        return cached


__all__ = ["PythonSyntax"]
