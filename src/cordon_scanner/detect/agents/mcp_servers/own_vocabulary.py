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

_WORD: Final = re.compile(r"(?<![\w.])\w++(?![\w])")
"""One run of word characters, not part of a dotted name: the candidates for `identifier_like`."""

_VERBS: Final = re.compile(r"\b(?i:call|calling|invoke|invoking|run|running|execute|use|using)\b")
"""The verbs after which a tool is named as something to call or use."""

_GAP: Final = frozenset(" \t\r\n:`'\"(")
_ARTICLES: Final = ("the ", "tool ")
_MAX_GAP: Final = 40


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
    def identifier_like(word: str) -> bool:
        """A snake_case or camelCase word: a tool or parameter name as an author writes one.

        Read in code, not by one pattern: a shape of repeated groups over the same characters is the
        superlinear kind (`reviews/release-080` 27-PERFORMANCE), and a word is short."""
        if len(word) < 3 or not word.isascii() or not word[0].isalpha():
            return False
        if "_" in word:
            parts = word.split("_")
            return all(part.isalnum() for part in parts)
        # camelCase: a lower-case run, then each hump an upper-case letter and at least one lower-case
        # letter or digit, with no second capital inside it.
        at = 0
        while at < len(word) and word[at].islower():
            at += 1
        if at == 0 or at == len(word):
            return False
        while at < len(word):
            if not word[at].isupper():
                return False
            at += 1
            start = at
            while at < len(word) and (word[at].islower() or word[at].isdigit()):
                at += 1
            if at == start:
                return False
        return True

    @staticmethod
    def words(text: str) -> frozenset[str]:
        """The identifier-like words of a text, lower-cased."""
        return frozenset(
            m.group(0).lower()
            for m in _WORD.finditer(text)
            if OwnVocabulary.identifier_like(m.group(0))
        )

    @staticmethod
    def called(text: str) -> frozenset[str]:
        """The identifiers a text names as tools to call or use, lower-cased: the ones sequencing is
        about (a description also names parameters and options that are no tool)."""
        found: set[str] = set()
        for verb in _VERBS.finditer(text):
            at, limit = verb.end(), min(len(text), verb.end() + _MAX_GAP)
            while at < limit and text[at] in _GAP:
                at += 1
            for article in _ARTICLES:
                if text[at : at + len(article)].lower() == article:
                    at += len(article)
                    while at < len(text) and text[at].isspace():
                        at += 1
                    break
            if at < len(text) and text[at] in "`'\"":
                at += 1
            word = _WORD.match(text, at)
            if word is not None and OwnVocabulary.identifier_like(word.group(0)):
                found.add(word.group(0).lower())
        return frozenset(found)

    @staticmethod
    def names_only(own: frozenset[str], text: str) -> bool:
        """Whether `text` names at least one identifier-like word and every one is in `own`."""
        found = OwnVocabulary.words(text)
        return bool(found) and found <= own
