"""What an MCP server declares itself: its tool names and parameter names (reviews/pypi-98/26).

A description or a returned message that sequences or conditions on identifiers the same server
declares is workflow guidance between its own tools ("you must first call `list_apis`"). One that names
an identifier the server does not declare reaches for another's tool, and stays what the rules read it as.
Only a text that names at least one identifier-like word is judged own, and only when every such word
is declared: a text that names nothing is not shown to be about the server's own tools here."""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

_IDENTIFIER_LIKE: Final = re.compile(
    r"(?<![\w.])(?:[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[a-z]+(?:[A-Z][a-z0-9]+)+)(?![\w])"
)
"""A snake_case or camelCase word: a tool or parameter name as an author writes one."""

_REGISTERED: Final = re.compile(
    r"""(?:\.tool\(\s*+(?:\{\s*+)?(?:name\s*:\s*+)?|\bregisterTool\(\s*|\bname\s*[:=]\s*)"""
    r"""["'`](?P<name>[A-Za-z][\w.-]{1,80})["'`]"""
)
_DECLARED_JS: Final = re.compile(r"\b(?:function|const|let|var)[ \t]+(?P<name>[A-Za-z_]\w{1,60})")


class OwnVocabulary:
    """The identifiers a server's source declares, and whether a text names only those."""

    MAX_TEXT: ClassVar[int] = 2_000_000

    @staticmethod
    def declared(text: str, path: str | None = None) -> frozenset[str]:
        """Lower-cased names of the functions and parameters a Python server defines and of the tools
        any server registers; for other languages the registered tool names and the functions, constants
        and variables they declare."""
        names: set[str] = set()
        text = text[: OwnVocabulary.MAX_TEXT]
        names.update(m.group("name").lower() for m in _REGISTERED.finditer(text))
        if path is None or path.endswith((".py", ".pyw")):
            try:
                tree = PythonSyntax.shared(text)
            except (SyntaxError, ValueError, RecursionError):
                # S2: a file that does not parse declares nothing here; no text is judged own by it
                return frozenset(names)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    names.add(node.name.lower())
                    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                    names.update(a.arg.lower() for a in arguments)
        else:
            names.update(m.group("name").lower() for m in _DECLARED_JS.finditer(text))
        return frozenset(names)

    @staticmethod
    def words(text: str) -> frozenset[str]:
        """The identifier-like words of a text, lower-cased."""
        return frozenset(m.group(0).lower() for m in _IDENTIFIER_LIKE.finditer(text))

    @staticmethod
    def names_only(own: frozenset[str], text: str) -> bool:
        """Whether `text` names at least one identifier-like word and every one is in `own`."""
        found = OwnVocabulary.words(text)
        return bool(found) and found <= own
