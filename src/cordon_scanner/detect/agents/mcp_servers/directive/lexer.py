"""Tokens of a source file in the languages an MCP server is written in besides Python and JavaScript.

Go, Rust, Java and C# have no syntax tree in this project, and the texts a server hands the agent in
them sit in string literals: a tool's description, an error message, a result, a prompt. This reads
a file into string, identifier and operator tokens, decoding each language's string forms (escapes,
raw strings, text blocks, verbatim and interpolated strings), so the reader can follow a text through
a constant or a concatenation to where it is used. Comments are dropped. Nothing is run.

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

_RUST: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<rawstr>b?r(?P<hashes>\#*)".*?"(?P=hashes))
   |(?P<str>b?"(?:[^"\\]|\\.)*")
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

_JAVA: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<block>\"\"\"[ \t]*\r?\n.*?(?<!\\)\"\"\")
   |(?P<str>"(?:[^"\\\n]|\\.)*")
   |(?P<char>'(?:[^'\\\n]|\\.)+')
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

_CSHARP: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z)|(?<![^\n])[ \t]*\#[^\n]*)
   |(?P<rawstr>\$*(?P<quotes>"{3,}).*?(?P=quotes))
   |(?P<verbatim>(?:\$@|@\$|@)"(?:[^"]|"")*")
   |(?P<interp>\$"(?:[^"\\\n]|\\.)*")
   |(?P<str>"(?:[^"\\\n]|\\.)*")
   |(?P<char>'(?:[^'\\\n]|\\.)+')
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
#: A name a C# interpolated string substitutes: `{name}`, `{name:format}`, `{name,width}`.
_CS_HOLE: Final = re.compile(r"\{([A-Za-z_]\w*)(?:[,:][^}\n]*)?\}")

_GO: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<raw>`[^`]*`)
   |(?P<str>"(?:[^"\\\n]|\\.)*")
   |(?P<rune>'(?:[^'\\\n]|\\.)+')
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
    def go(text: str) -> list[Token]:
        out: list[Token] = []
        line = 1
        for match in _GO.finditer(text):
            kind = match.lastgroup
            value = match.group()
            start = match.start()
            if kind == "nl":
                line += 1
                continue
            if kind in ("comment", "rune", "num", "other"):
                line += value.count("\n")
                continue
            if kind == "str":
                out.append(Token("str", Lexer.unescape(value[1:-1]), start, match.end(), line))
            elif kind == "raw":
                out.append(Token("str", value[1:-1], start, match.end(), line))
                line += value.count("\n")
            else:
                out.append(Token(str(kind), value, start, match.end(), line))
            if len(out) >= MAX_TOKENS:
                break
        return out

    @staticmethod
    def rust(text: str) -> list[Token]:
        out: list[Token] = []
        line = 1
        for match in _RUST.finditer(text):
            kind = match.lastgroup
            value = match.group()
            start = match.start()
            if kind == "nl":
                line += 1
                continue
            if kind in ("comment", "char", "life", "num", "other"):
                line += value.count("\n")
                continue
            if kind in ("str", "rawstr"):
                if kind == "rawstr":
                    body = value.split('"', 1)[1].rsplit('"', 1)[0]
                else:
                    body = Lexer.unescape(_CONTINUATION.sub("", value[value.index('"') + 1 : -1]))
                body = _INLINE_NAME.sub(lambda m: MARK + m.group(1) + MARK, body)
                out.append(Token("str", body, start, match.end(), line))
                line += value.count("\n")
            else:
                out.append(Token(str(kind), value, start, match.end(), line))
            if len(out) >= MAX_TOKENS:
                break
        return out

    @staticmethod
    def dedent(body: str) -> str:
        """A text block's content without its incidental indentation (the least common one) and the
        line break after its opening delimiter."""
        lines = body.split("\n")[1:]
        margins = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        if lines and not lines[-1].strip():
            margins.append(len(lines[-1]))
        cut = min(margins) if margins else 0
        return "\n".join(line[cut:] for line in lines)

    @staticmethod
    def java(text: str) -> list[Token]:
        out: list[Token] = []
        line = 1
        for match in _JAVA.finditer(text):
            kind = match.lastgroup
            value = match.group()
            start = match.start()
            if kind == "nl":
                line += 1
                continue
            if kind in ("comment", "char", "num", "other"):
                line += value.count("\n")
                continue
            if kind == "block":
                body = Lexer.unescape(Lexer.dedent(value[3:-3]).replace("\\\n", ""))
                out.append(Token("str", body, start, match.end(), line))
                line += value.count("\n")
            elif kind == "str":
                out.append(Token("str", Lexer.unescape(value[1:-1]), start, match.end(), line))
            else:
                out.append(Token(str(kind), value, start, match.end(), line))
            if len(out) >= MAX_TOKENS:
                break
        return out

    @staticmethod
    def interpolated(body: str) -> str:
        """The body of a C# interpolated string with each `{name}` hole a marker and `{{` `}}` braces."""
        body = body.replace("{{", "\x01").replace("}}", "\x02")
        body = _CS_HOLE.sub(lambda m: MARK + m.group(1) + MARK, body)
        return body.replace("\x01", "{").replace("\x02", "}")

    @staticmethod
    def csharp(text: str) -> list[Token]:
        out: list[Token] = []
        line = 1
        for match in _CSHARP.finditer(text):
            kind = match.lastgroup
            value = match.group()
            start = match.start()
            if kind == "nl":
                line += 1
                continue
            if kind in ("comment", "char", "num", "other"):
                line += value.count("\n")
                continue
            if kind == "rawstr":
                dollars = len(value) - len(value.lstrip("$"))
                quotes = len(match.group("quotes"))
                body = Lexer.dedent(value[dollars + quotes : -quotes])
                body = Lexer.interpolated(body) if dollars else body
                out.append(Token("str", body, start, match.end(), line))
                line += value.count("\n")
            elif kind == "verbatim":
                interpolated = "$" in value[:2]
                body = value[value.index('"') + 1 : -1].replace('""', '"')
                out.append(
                    Token(
                        "str",
                        Lexer.interpolated(body) if interpolated else body,
                        start,
                        match.end(),
                        line,
                    )
                )
                line += value.count("\n")
            elif kind == "interp":
                body = Lexer.interpolated(Lexer.unescape(value[2:-1]))
                out.append(Token("str", body, start, match.end(), line))
            elif kind == "str":
                out.append(Token("str", Lexer.unescape(value[1:-1]), start, match.end(), line))
            else:
                out.append(Token(str(kind), value, start, match.end(), line))
            if len(out) >= MAX_TOKENS:
                break
        return out


#: The tokenizer of each language.
LANGUAGES: Final = {
    "go": Lexer.go,
    "rust": Lexer.rust,
    "java": Lexer.java,
    "csharp": Lexer.csharp,
}

__all__ = ["LANGUAGES", "MARK", "MAX_CHARS", "Lexer", "Token"]
