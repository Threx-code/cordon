"""Tokens of a source file in the languages an MCP server is written in besides Python and JavaScript.

Go, Rust, Java and C# have no syntax tree in this project, and the texts a server hands the agent in
them sit in string literals: a tool's description, an error message, a result, a prompt. This reads
a file into string, identifier and operator tokens, decoding each language's string forms (escapes,
raw strings, text blocks, verbatim and interpolated strings), so the reader can follow a text through
a constant or a concatenation to where it is used. Comments are dropped. Nothing is run.

The file is read once from left to right, one token at a time, so no text is read twice by a pattern
that starts again inside a run an earlier attempt read. A string that does not end is the one place
an attempt reads on to a line's or the file's end: it is remembered, because a later opener on the
same line (or, for a raw string or a text block, in the file) cannot end either.

An interpolated string keeps the names it substitutes as a marker (`\\x00name\\x00`), which the reader
replaces with the text of the constant of that name when the file defines one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: Beyond this many characters or tokens a file is not read.
MAX_CHARS: Final = 1_500_000
MAX_TOKENS: Final = 400_000
#: The marker around the name of a value an interpolated string substitutes.
MARK: Final = "\x00"


@dataclass(frozen=True, slots=True)
class Token:
    """One token: `kind` is `str` (its decoded value), `id` or `op`; `start` and `end` are character
    offsets in the file and `line` the line the token starts on."""

    kind: str
    text: str
    start: int
    end: int
    line: int


_COMMON_OPS: Final = r":=|==|!=|<=|>=|&&|\|\||\.\.\.|\+\+|--|[-+*/%&|^<>=!:;,.(){}\[\]?~@#$]"
_ESCAPES: Final = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
}
_ESCAPE: Final = re.compile(
    r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|([0-7]{3})|(.))",
    re.S,
)

#: A name a Rust format string substitutes: `{name}` (not `{{`, not `{0}`, not `{name:?}`).
_INLINE_NAME: Final = re.compile(r"(?<!\{)\{([A-Za-z_]\w*)\}(?!\})")
_CONTINUATION: Final = re.compile(r"\\\n[ \t\r\n]*")
#: A name a C# interpolated string substitutes: `{name}`, `{name:format}`, `{name,width}`.
_CS_HOLE: Final = re.compile(r"\{([A-Za-z_]\w*)(?:[,:][^}\n]*)?\}")

# Each language's tokens other than the body of a quoted string, which is read from the quote on by
# its own pattern below. `quote` is the opening quote of such a string; `raw`, `rawopen` and `blockopen`
# open a string that ends at a closer found in the text, not by a pattern.
_GO: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<raw>`[^`]*`)
   |(?P<quote>")
   |(?P<rune>'(?:[^'\\\n]|\\'|\\[^'\n]{1,10})')
   |(?P<id>[^\W\d]\w*)
   |(?P<num>\d[\w.]*)
   |(?P<op>"""
    + _COMMON_OPS
    + r""")
   |(?P<nl>\n)
   |(?P<other>.)
    """,
    re.X | re.S,
)
_GO_STRING: Final = re.compile(r'"(?:[^"\\\n]++|\\.)*+"', re.S)

_RUST: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<rawopen>b?r\#*")
   |(?P<quote>b?")
   |(?P<char>'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|.)|[^'\\\n])')
   |(?P<life>'[A-Za-z_]\w*)
   |(?P<id>(?:r\#)?[^\W\d]\w*)
   |(?P<num>\d[\w.]*)
   |(?P<op>=>|->|::|\.\.=|"""
    + _COMMON_OPS
    + r""")
   |(?P<nl>\n)
   |(?P<other>.)
    """,
    re.X | re.S,
)
_RUST_STRING: Final = re.compile(r'"(?:[^"\\]++|\\.)*+"', re.S)

_JAVA: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<blockopen>\"\"\"[ \t]*\r?\n)
   |(?P<quote>")
   |(?P<char>'(?:[^'\\\n]|\\'|\\[^'\n]{1,10})')
   |(?P<id>[^\W\d]\w*)
   |(?P<num>\d[\w.]*)
   |(?P<op>->|::|"""
    + _COMMON_OPS
    + r""")
   |(?P<nl>\n)
   |(?P<other>.)
    """,
    re.X | re.S,
)
_JAVA_STRING: Final = re.compile(r'"(?:[^"\\\n]++|\\.)*+"', re.S)

_CSHARP: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z)|(?<![^\n])[ \t]*\#[^\n]*)
   |(?P<rawopen>\$*"{3,})
   |(?P<verbatim>(?:\$@|@\$|@)")
   |(?P<interp>\$")
   |(?P<quote>")
   |(?P<char>'(?:[^'\\\n]|\\'|\\[^'\n]{1,10})')
   |(?P<id>@?[^\W\d]\w*)
   |(?P<num>\d[\w.]*)
   |(?P<op>=>|\?\?|"""
    + _COMMON_OPS
    + r""")
   |(?P<nl>\n)
   |(?P<other>.)
    """,
    re.X | re.S,
)
_CS_STRING: Final = re.compile(r'"(?:[^"\\\n]++|\\.)*+"', re.S)
_CS_VERBATIM: Final = re.compile(r'"(?:[^"]++|"")*+"', re.S)


class _Closers:
    """Where a raw string or a text block ends, and where a quoted string that does not end gave up.
    A closer missing after one opener is missing after every later one, so it is looked for once."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.missing: set[str] = set()
        #: The offset up to which a quote of each kind cannot open a string that ends.
        self.dead: dict[str, int] = {}

    def end(self, closer: str, begin: int, *, escapable: bool = False) -> int:
        """Where `closer` starts at or after `begin` (one not escaped by a backslash when `escapable`),
        or -1."""
        if closer in self.missing:
            return -1
        found = self.text.find(closer, begin)
        while escapable and found > begin and self.text[found - 1] == "\\":
            found = self.text.find(closer, found + 1)
        if found < 0:
            self.missing.add(closer)
        return found

    def may_open(self, kind: str, at: int) -> bool:
        return at >= self.dead.get(kind, 0)

    def gave_up(self, kind: str, at: int, *, to_end: bool) -> None:
        """A string opened at `at` did not end: none opened before the end of its line (of the file when
        it may span lines) will."""
        if to_end:
            self.dead[kind] = len(self.text)
            return
        newline = self.text.find("\n", at)
        self.dead[kind] = len(self.text) if newline < 0 else newline


class Lexer:
    """`Lexer.tokens(text, language)`: the tokens of a file, or none when it is too large."""

    @staticmethod
    def unescape(body: str) -> str:
        """A string body with its backslash escapes decoded (a malformed one is kept as written)."""

        def one(match: re.Match[str]) -> str:
            braced, short, long, hexa, octal, plain = match.groups()
            digits = braced or short or long or hexa
            if digits:
                try:
                    return chr(int(digits, 16))
                except (ValueError, OverflowError):
                    return match.group(0)
            if octal:
                return chr(int(octal, 8))
            return _ESCAPES.get(plain, plain)

        return _ESCAPE.sub(one, body) if "\\" in body else body

    @staticmethod
    def tokens(text: str, language: str) -> list[Token]:
        if len(text) > MAX_CHARS or language not in LANGUAGES:
            return []
        return LANGUAGES[language](text)

    @staticmethod
    def dedent(body: str) -> str:
        """A text block's lines (the content after the opening line break) without their incidental
        indentation: the least common one, the closing delimiter's line counting when it is blank."""
        if "\n" not in body:
            return body
        lines = body.split("\n")
        margins = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        if not lines[-1].strip():
            margins.append(len(lines[-1]))
        cut = min(margins) if margins else 0
        return "\n".join(line[cut:] for line in lines)

    @staticmethod
    def interpolated(body: str) -> str:
        """The body of a C# interpolated string with each `{name}` hole a marker and `{{` `}}` braces."""
        body = body.replace("{{", "\x01").replace("}}", "\x02")
        body = _CS_HOLE.sub(lambda m: MARK + m.group(1) + MARK, body)
        return body.replace("\x01", "{").replace("\x02", "}")

    @staticmethod
    def go(text: str) -> list[Token]:
        out: list[Token] = []
        line, pos, size = 1, 0, len(text)
        closers = _Closers(text)
        while pos < size and len(out) < MAX_TOKENS:
            match = _GO.match(text, pos)
            if match is None:
                break
            start, kind = pos, match.lastgroup
            pos = match.end()
            if kind == "quote":
                string = _GO_STRING.match(text, start) if closers.may_open("go", start) else None
                if string is None:
                    closers.gave_up("go", start, to_end=False)
                else:
                    pos = string.end()
                    value = Lexer.unescape(string.group()[1:-1])
                    out.append(Token("str", value, start, pos, line))
            elif kind == "raw":
                out.append(Token("str", match.group()[1:-1], start, pos, line))
            elif kind in ("id", "op"):
                out.append(Token(str(kind), match.group(), start, pos, line))
            line += text.count("\n", start, pos)
        return out

    @staticmethod
    def rust(text: str) -> list[Token]:
        out: list[Token] = []
        line, pos, size = 1, 0, len(text)
        closers = _Closers(text)
        while pos < size and len(out) < MAX_TOKENS:
            match = _RUST.match(text, pos)
            if match is None:
                break
            start, kind = pos, match.lastgroup
            pos = match.end()
            body: str | None = None
            if kind == "rawopen":
                closer = '"' + "#" * match.group().count("#")
                end = closers.end(closer, pos)
                if end >= 0:
                    body = text[pos:end]
                    pos = end + len(closer)
            elif kind == "quote":
                quote = pos - 1
                string = (
                    _RUST_STRING.match(text, quote) if closers.may_open("rust", quote) else None
                )
                if string is None:
                    closers.gave_up("rust", quote, to_end=True)
                else:
                    pos = string.end()
                    body = Lexer.unescape(_CONTINUATION.sub("", string.group()[1:-1]))
            if body is not None:
                body = _INLINE_NAME.sub(lambda m: MARK + m.group(1) + MARK, body)
                out.append(Token("str", body, start, pos, line))
            elif kind in ("id", "op"):
                out.append(Token(str(kind), match.group(), start, pos, line))
            line += text.count("\n", start, pos)
        return out

    @staticmethod
    def java(text: str) -> list[Token]:
        out: list[Token] = []
        line, pos, size = 1, 0, len(text)
        closers = _Closers(text)
        while pos < size and len(out) < MAX_TOKENS:
            match = _JAVA.match(text, pos)
            if match is None:
                break
            start, kind = pos, match.lastgroup
            pos = match.end()
            if kind == "blockopen":
                end = closers.end('"""', pos, escapable=True)
                if end >= 0:
                    body = Lexer.unescape(Lexer.dedent(text[pos:end]).replace("\\\n", ""))
                    out.append(Token("str", body, start, end + 3, line))
                    pos = end + 3
            elif kind == "quote":
                string = (
                    _JAVA_STRING.match(text, start) if closers.may_open("java", start) else None
                )
                if string is None:
                    closers.gave_up("java", start, to_end=False)
                else:
                    pos = string.end()
                    out.append(Token("str", Lexer.unescape(string.group()[1:-1]), start, pos, line))
            elif kind in ("id", "op"):
                out.append(Token(str(kind), match.group(), start, pos, line))
            line += text.count("\n", start, pos)
        return out

    @staticmethod
    def csharp(text: str) -> list[Token]:
        out: list[Token] = []
        line, pos, size = 1, 0, len(text)
        closers = _Closers(text)
        while pos < size and len(out) < MAX_TOKENS:
            match = _CSHARP.match(text, pos)
            if match is None:
                break
            start, kind = pos, match.lastgroup
            pos = match.end()
            body: str | None = None
            if kind == "rawopen":
                opener = match.group()
                end = closers.end('"' * opener.count('"'), pos)
                if end >= 0:
                    first, _, rest = text[pos:end].partition("\n")
                    content = Lexer.dedent(rest) if rest and not first.strip() else text[pos:end]
                    body = Lexer.interpolated(content) if "$" in opener else content
                    pos = end + opener.count('"')
            elif kind == "verbatim":
                quote = pos - 1
                string = (
                    _CS_VERBATIM.match(text, quote) if closers.may_open("verbatim", quote) else None
                )
                if string is None:
                    closers.gave_up("verbatim", quote, to_end=True)
                else:
                    pos = string.end()
                    content = string.group()[1:-1].replace('""', '"')
                    body = Lexer.interpolated(content) if "$" in match.group() else content
            elif kind in ("interp", "quote"):
                quote = pos - 1
                string = (
                    _CS_STRING.match(text, quote) if closers.may_open("string", quote) else None
                )
                if string is None:
                    closers.gave_up("string", quote, to_end=False)
                else:
                    pos = string.end()
                    content = Lexer.unescape(string.group()[1:-1])
                    body = Lexer.interpolated(content) if kind == "interp" else content
            if body is not None:
                out.append(Token("str", body, start, pos, line))
            elif kind in ("id", "op"):
                out.append(Token(str(kind), match.group(), start, pos, line))
            line += text.count("\n", start, pos)
        return out


#: The tokenizer of each language.
LANGUAGES: Final = {
    "go": Lexer.go,
    "rust": Lexer.rust,
    "java": Lexer.java,
    "csharp": Lexer.csharp,
}

__all__ = ["LANGUAGES", "MARK", "MAX_CHARS", "Lexer", "Token"]
