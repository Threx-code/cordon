"""The language a file's bytes are, where its name says another (evasion suite B, item 39).

A file is read as the language its name gives (`LanguageRegistry.of_file`), and its content is sniffed
only when the name says nothing. So Python named `run.js` was JavaScript to every rule: inside a zip
inside the package, unpacked and run by `python` at install, it passed with nothing said (eleven
probes: nested archives, an archive named `notes.txt`, a zip appended to a PNG).

The name stays the first reading, never replaced: a reading that took the name's language away would
let an attacker switch the JavaScript rules off by adding one Python line inside a template string. A
second reading is added beside it, as its own unit, when the bytes are the other language by that
language's own strict parser -- Python's `ast`, Cordon's JavaScript parser with no statement it could
not read -- and carry at least one statement form only that language has. Shell has no strict parser
here, so a shell reading needs two of its structural forms and the name's own parser rejecting the
file. Measured on the npm and PyPI work sets (3 Nov, 88,086 archives, each code-named member's first
8 KiB): Python in a JavaScript-named file that `ast` accepts was in malware only.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import ClassVar

from cordon_scanner.analysis.shared.languages import LanguageRegistry


class ContentLanguage:
    """`second_reading(text, language)`: the other language the text is, or None."""

    FAMILY: ClassVar[dict[str, str]] = {
        "javascript": "javascript",
        "typescript": "javascript",
        "python": "python",
        "shell": "shell",
    }
    """The name's language, by the parser that would check it."""

    EXCLUSIVE: ClassVar[dict[str, tuple[re.Pattern[str], ...]]] = {
        "python": tuple(
            re.compile(p, re.MULTILINE)
            for p in (
                r"^[ \t]*from[ \t]+[\w.]{1,80}[ \t]+import[ \t]+[\w*(]",
                r"^[ \t]*import[ \t]+[\w.]{1,80}(?:[ \t]+as[ \t]+\w{1,40})?"
                r"(?:[ \t]*,[ \t]*[\w.]{1,80}(?:[ \t]+as[ \t]+\w{1,40})?){0,20}[ \t]*(?:#[^\n]*)?$",
                r"^[ \t]*(?:async[ \t]+)?def[ \t]+\w{1,80}[ \t]*\([^)\n]{0,300}\)[ \t]*"
                r"(?:->[^:\n]{1,80})?:[ \t]*(?:#[^\n]*)?$",
                r"^[ \t]*if[ \t]+__name__[ \t]*==[ \t]*['\"]__main__['\"][ \t]*:",
                r"^[ \t]*class[ \t]+\w{1,80}[ \t]*(?:\([^)\n]{0,300}\))?[ \t]*:[ \t]*$",
            )
        ),
        "javascript": tuple(
            re.compile(p, re.MULTILINE)
            for p in (
                r"\brequire[ \t]*\([ \t]*[\"'`]",
                r"\bmodule[ \t]*\.[ \t]*exports\b",
                r"^[ \t]*(?:const|let|var)[ \t]+[\w$]{1,80}[ \t]*=",
                r"=>[ \t]*\{",
                r"^[ \t]*export[ \t]+(?:default|const|function|class)\b",
            )
        ),
        "shell": tuple(
            re.compile(p, re.MULTILINE)
            for p in (
                r"^[ \t]*fi[ \t]*$",
                r"^[ \t]*(?:then|done|esac)[ \t]*$",
                r"^[ \t]*for[ \t]+\w{1,40}[ \t]+in[ \t][^\n]{0,200};[ \t]*do\b",
                r"^[ \t]*(?:if|elif)[ \t]+\[\[?[ \t]",
            )
        ),
    }
    """Statement forms only that language has: a line no JavaScript, Python or shell file of the other
    two holds outside a string."""

    SHELL_FORMS: ClassVar[int] = 2
    """Shell has no strict parser here: two structural forms, with the name's parser rejecting the file."""

    @staticmethod
    def parses(text: str, language: str, *, typescript: bool = False) -> bool | None:
        """Whether the text is that language by its strict parser; None for one without a parser.
        JavaScript is read with JSX, and as TypeScript when the name says so: a `.ts` file checked
        as plain JavaScript is rejected, and its shell completion script in a template string was
        then read as shell (measured: 18 TypeScript files on the npm work set)."""
        if language == "python":
            from cordon_scanner.analysis.python.module_facts import StatementTrees
            from cordon_scanner.analysis.python.pysyntax import PythonSyntax

            # A statement at a time, as the Python reader parses a large module (note 80): a
            # module's whole tree is never held for a yes or no.
            spans = StatementTrees.pieces(text) or [(0, len(text))]
            try:
                for start, end in spans:
                    piece = text[start:end]
                    if piece.strip():
                        PythonSyntax.parse(piece)
                    del piece
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return False
            return True
        if language == "javascript":
            from cordon_scanner.analysis.javascript.front.parser import Parser

            parser = Parser(text, typescript=typescript, jsx=True)
            parser.program()
            return parser.errors == 0
        return None

    DATA: ClassVar[frozenset[str | None]] = frozenset({None, "markdown"})
    """Names that give no code language -- `run.txt`, `notes.cfg`, `README.md`. Read as Python or
    JavaScript only by that language's strict parser, never as shell: a document of shell
    commands is documentation (`LanguageRegistry.CONTENT_SIGNATURES`), and a document is never
    a whole Python or JavaScript program by accident. Structured formats (JSON, YAML, TOML) are
    defined by their own parsers and are not re-read."""

    @staticmethod
    def second_reading(
        text: str, language: str | None, whole: Callable[[], str] | None = None
    ) -> str | None:
        """The language the text also is, beside the one its name gives; None when it is only that.

        `text` may be the file's head alone (`MAX_SNIFF_BYTES`) with `whole` giving the file: the
        whole text is decoded only for a file whose head holds another language's form (note 80).
        """
        if not text:
            return None
        head = text[: LanguageRegistry.MAX_SNIFF_BYTES]
        full = whole or (lambda: text)
        if language in ContentLanguage.DATA:
            for other in ("python", "javascript"):
                forms = ContentLanguage.EXCLUSIVE[other]
                if any(form.search(head) for form in forms) and ContentLanguage.parses(
                    full(), other
                ):
                    return other
            return None
        named = ContentLanguage.FAMILY.get(language or "")
        if named is None:
            return None
        for other, forms in ContentLanguage.EXCLUSIVE.items():
            if other == named:
                continue
            hits = sum(1 for form in forms if form.search(head))
            if not hits:
                continue
            body = full()
            accepted = ContentLanguage.parses(body, other)
            if accepted:
                return other
            if (
                accepted is None
                and hits >= ContentLanguage.SHELL_FORMS
                and ContentLanguage.parses(body, named, typescript=language == "typescript")
                is False
            ):
                return other
        return None


__all__ = ["ContentLanguage"]
