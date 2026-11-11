"""Packages installed from an index the user did not choose.

`pip install --extra-index-url https://x/simple dep` makes pip look for `dep` on a second index as
well, and take whichever copy has the higher version: the dependency-confusion shape. `--index-url`
replaces the user's index, `--find-links` adds a page of files, and `--trusted-host` (or a library's
`trust_all_hosts=True`) turns the certificate check off for the host. Run by an install hook, any of
them lets whoever runs that index put code on the machine. A build backend that installs its build
requirements from the default index passes none of these.

`lines` returns the line of each call that does it: a process started with a pip install and one of
those flags (an argv list or a shell string), or any call handed `trust_all_hosts=True`,
`trusted_host=` or a `trusted_hosts=` list.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.py_flow import PythonValueFlow

PIP_WORD: Final = re.compile(r"\bpip[0-9.]*\b")
INSTALL_WORD: Final = re.compile(r"\binstall\b")
INDEX_FLAG: Final = re.compile(
    r"(?<![\w-])(?:--index-url|--extra-index-url|--trusted-host|--find-links|-i|-f)(?![\w-])", re.I
)
TRUST_KEYWORDS: Final = frozenset({"trust_all_hosts", "trusted_host", "trusted_hosts", "trust_all"})


class ForeignIndex:
    """The installs from another index in one syntax tree."""

    PROCESS: ClassVar[frozenset[str]] = PythonValueFlow.PROCESS

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        out: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if any(
                k.arg in TRUST_KEYWORDS and not (isinstance(k.value, ast.Constant) and k.value.value in (False, None, ""))
                for k in node.keywords
            ):
                out.add(node.lineno)
                continue
            name = PythonValueFlow.dotted(node.func) or ""
            short = PythonValueFlow.name(node.func) or ""
            if (name in cls.PROCESS or short in cls.PROCESS or name.endswith("pip.main")) and node.args:
                text = " ".join(
                    p.value for p in ast.walk(node.args[0]) if isinstance(p, ast.Constant) and isinstance(p.value, str)
                )
                if (name.endswith("pip.main") and "install" in text and INDEX_FLAG.search(text)) or (PIP_WORD.search(text) and INSTALL_WORD.search(text) and INDEX_FLAG.search(text)):
                    out.add(node.lineno)
        return sorted(out)


__all__ = ["ForeignIndex"]
