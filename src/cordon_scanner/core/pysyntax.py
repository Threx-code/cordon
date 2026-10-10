"""Python source parsed as data.

`ast.parse` warns about the source it reads: `"\\h"`, an invalid escape in a scanned file, is a
`SyntaxWarning` (a `DeprecationWarning` before 3.12), written to the scanner's own stderr once per
literal. Scanning stable-diffusion printed seven of them into a CI log, which reads as the
scanner failing. A scanned file's escapes are its author's business; the warnings are not ours to
print, so every parse of untrusted source goes through here.
"""

from __future__ import annotations

import ast
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


__all__ = ["PythonSyntax"]
