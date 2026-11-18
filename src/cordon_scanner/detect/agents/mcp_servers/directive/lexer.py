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


#: The tokenizer of each language.
LANGUAGES: Final = {"go": Lexer.go}

__all__ = ["LANGUAGES", "MARK", "MAX_CHARS", "Lexer", "Token"]
