"""The tokens of a JavaScript or TypeScript source: one linear pass, written by this project.

The first stage of Cordon's own JavaScript front end (`reviews/self-improving/08-JS-FRONT-END.md`),
which replaces the tree-sitter extra: no parser written elsewhere ever reads an attacker's file.

A state machine over the characters. The only regular expressions are runs of one character
class (spaces, a name's ASCII characters, a line's characters, a string's plain characters): each
is a single forward scan in C that cannot backtrack, and the state machine takes over at every
escape and every character the class leaves out. No input can make the lexer backtrack, and every
token costs time in proportion to its length. A malformed construct -- an unterminated string, a stray character -- becomes an
`error` token and lexing goes on: what follows is still read.

Two things depend on the grammar rather than the characters, and both are settled exactly:

- whether `/` opens a regular expression or divides is the parser's to say (`next(regex=...)`):
  only it knows whether an operand is expected;
- whether `}` closes a block or a template substitution is tracked here, on a stack of the braces
  and `${` opened, so `` `a${ {b: 1}.b }c` `` reads as the template it is.

Positions are character offsets; `line_of` and `column_of` place them.
"""

from __future__ import annotations

import bisect
import re
from typing import ClassVar


class Token:
    """One token: its `kind`, its `value` (the text, or for a string or template part its cooked
    value), its span, and whether a line break precedes it (automatic semicolon insertion)."""

    __slots__ = ("end", "kind", "newline", "start", "value")

    def __init__(self, kind: str, value: str, start: int, end: int, newline: bool) -> None:
        self.kind, self.value, self.start, self.end, self.newline = kind, value, start, end, newline

    def __repr__(self) -> str:
        return f"Token({self.kind}, {self.value!r}, {self.start})"


class Lexer:
    """`next(regex=...)` gives the next token; `kind` is one of `name`, `private`, `number`,
    `string`, `template` (whole, without substitutions), `template_head`, `template_middle`,
    `template_tail`, `regex`, `punct`, `error`, `eof`."""

    #: Every punctuator of more than one character, by first character, longest first.
    PUNCTUATORS: ClassVar[dict[str, tuple[str, ...]]] = {
        ">": (">>>=", ">>>", ">>=", ">>", ">="),
        "<": ("<<=", "<<", "<="),
        "=": ("===", "==", "=>"),
        "!": ("!==", "!="),
        "*": ("**=", "**", "*="),
        "&": ("&&=", "&&", "&="),
        "|": ("||=", "||", "|="),
        "?": ("??=", "??", "?."),
        ".": ("...",),
        "+": ("++", "+="),
        "-": ("--", "-="),
        "%": ("%=",),
        "^": ("^=",),
        "/": ("/=",),
    }
    SINGLE: ClassVar[frozenset[str]] = frozenset("{}()[];,<>+-*/%&|^!~?:=.@#")
    LINE_BREAKS: ClassVar[frozenset[str]] = frozenset(map(chr, (0x0A, 0x0D, 0x2028, 0x2029)))
    #: Tab, vertical tab, form feed, space, no-break space, byte order mark and the Unicode
    #: space separators (category Zs).
    SPACE: ClassVar[frozenset[str]] = frozenset(
        map(
            chr,
            (
                0x09,
                0x0B,
                0x0C,
                0x20,
                0xA0,
                0xFEFF,
                0x1680,
                *range(0x2000, 0x200B),
                0x202F,
                0x205F,
                0x3000,
            ),
        )
    )
    #: Runs of one character class, each a linear scan (see the module docstring).
    SPACE_RUN: ClassVar[re.Pattern[str]] = re.compile("[" + "".join(sorted(SPACE)) + "]+")
    BREAK: ClassVar[re.Pattern[str]] = re.compile("[" + "".join(sorted(LINE_BREAKS)) + "]")
    LINE_REST: ClassVar[re.Pattern[str]] = re.compile("[^" + "".join(sorted(LINE_BREAKS)) + "]*")
    ASCII_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_$]*")
    PLAIN: ClassVar[dict[str, re.Pattern[str]]] = {
        q: re.compile("[^" + q + "\\\\\n\r]*") for q in "'\""
    }

    ESCAPES: ClassVar[dict[str, str]] = {
        "n": "\n",
        "t": "\t",
        "r": "\r",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\0",
    }

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.newline = False
        #: Open `{` (False) and `${` (True), so a `}` knows which it closes.
        self.braces: list[bool] = []
        self._lines: list[int] | None = None
        if text.startswith("#!"):  # a hashbang line is a comment
            end = self._line_end(0)
            self.pos = end

    # -- placement ------------------------------------------------------------

    def line_of(self, offset: int) -> int:
        if self._lines is None:
            starts, at = [0], self.text.find("\n")
            while at >= 0:
                starts.append(at + 1)
                at = self.text.find("\n", at + 1)
            self._lines = starts
        return bisect.bisect_right(self._lines, offset)

    def column_of(self, offset: int) -> int:
        line = self.line_of(offset)
        return offset - (self._lines or [0])[line - 1]

    # -- tokens ---------------------------------------------------------------

    def next(self, *, regex: bool = False) -> Token:
        self._skip_trivia()
        text, pos, n = self.text, self.pos, len(self.text)
        newline, self.newline = self.newline, False
        if pos >= n:
            return Token("eof", "", n, n, newline)
        c = text[pos]
        if (
            c.isalpha()
            or c in "_$"
            or (ord(c) > 127 and c.isidentifier())
            or text.startswith("\\u", pos)
        ):
            return self._name("name", pos, newline)
        if c == "#" and pos + 1 < n and (text[pos + 1].isalpha() or text[pos + 1] in "_$"):
            return self._name("private", pos + 1, newline, start=pos)
        if c.isdigit() or (c == "." and pos + 1 < n and text[pos + 1].isdigit()):
            return self._number(pos, newline)
        if c in "'\"":
            return self._string(pos, c, newline)
        if c == "`":
            return self._template(pos + 1, pos, "template", newline)
        if c == "/" and regex:
            return self._regex(pos, newline)
        if c == "}" and self.braces and self.braces[-1]:
            self.braces.pop()
            return self._template(pos + 1, pos, "template_middle", newline)
        return self._punct(pos, c, newline)

    def _skip_trivia(self) -> None:
        text, n = self.text, len(self.text)
        pos = self.pos
        space_run, brk = Lexer.SPACE_RUN.match, Lexer.BREAK.search
        while pos < n:
            c = text[pos]
            if c in Lexer.LINE_BREAKS:
                self.newline = True
                pos += 1
            elif c in Lexer.SPACE:
                pos = space_run(text, pos).end()
            elif c == "/" and text.startswith("//", pos):
                pos = self._line_end(pos)
            elif c == "/" and text.startswith("/*", pos):
                close = text.find("*/", pos + 2)
                end = n if close < 0 else close + 2
                if brk(text, pos, end):
                    self.newline = True
                pos = end
            elif c == "<" and text.startswith("<!--", pos):  # an HTML-like comment, in a script
                pos = self._line_end(pos)
            else:
                break
        self.pos = pos

    def _line_end(self, pos: int) -> int:
        return Lexer.LINE_REST.match(self.text, pos).end()

    def _name(self, kind: str, pos: int, newline: bool, start: int | None = None) -> Token:
        text, n = self.text, len(self.text)
        begin = pos if start is None else start
        end = Lexer.ASCII_NAME.match(text, pos).end()
        if end >= n or (text[end] != "\\" and ord(text[end]) < 128):  # all ASCII: one scan
            self.pos = end
            return Token(kind, text[pos:end], begin, end, newline)
        parts: list[str] = [text[pos:end]]
        pos = end
        while pos < n:
            c = text[pos]
            if c.isalnum() or c in "_$\u200c\u200d" or (ord(c) > 127 and ("a" + c).isidentifier()):
                parts.append(c)
                pos += 1
            elif c == "\\" and text.startswith("\\u", pos):
                value, pos = self._unicode_escape(pos + 2)
                parts.append(value)
            else:
                break
        self.pos = pos
        return Token(kind, "".join(parts), begin, pos, newline)

    def _number(self, pos: int, newline: bool) -> Token:
        text, n = self.text, len(self.text)
        start = pos
        if text[pos] == "0" and pos + 1 < n and text[pos + 1] in "xXoObB":
            digits = {"x": "0123456789abcdefABCDEF_", "o": "01234567_", "b": "01_"}[
                text[pos + 1].lower()
            ]
            pos += 2
            while pos < n and text[pos] in digits:
                pos += 1
        else:
            while pos < n and (text[pos].isdigit() or text[pos] == "_"):
                pos += 1
            if pos < n and text[pos] == ".":
                pos += 1
                while pos < n and (text[pos].isdigit() or text[pos] == "_"):
                    pos += 1
            if pos < n and text[pos] in "eE":
                k = pos + 1
                if k < n and text[k] in "+-":
                    k += 1
                if k < n and text[k].isdigit():
                    pos = k
                    while pos < n and text[pos].isdigit():
                        pos += 1
        if pos < n and text[pos] == "n":  # a BigInt
            pos += 1
        self.pos = pos
        return Token("number", text[start:pos], start, pos, newline)

    def _string(self, pos: int, quote: str, newline: bool) -> Token:
        text, n = self.text, len(self.text)
        start, pos = pos, pos + 1
        plain = Lexer.PLAIN[quote].match
        end = plain(text, pos).end()
        if end < n and text[end] == quote:  # no escape: the body as it stands
            self.pos = end + 1
            return Token("string", text[pos:end], start, end + 1, newline)
        out: list[str] = []
        while pos < n:
            end = plain(text, pos).end()
            if end > pos:
                out.append(text[pos:end])
                pos = end
                continue
            c = text[pos]
            if c == quote:
                self.pos = pos + 1
                return Token("string", "".join(out), start, pos + 1, newline)
            if c in "\n\r":  # unterminated on its line: what it held is not code
                break
            if c == "\\":
                value, pos = self._escape(pos + 1)
                out.append(value)
                continue
            out.append(c)
            pos += 1
        self.pos = pos
        return Token("error", text[start:pos], start, pos, newline)

    def _template(self, pos: int, start: int, kind: str, newline: bool) -> Token:
        """A template from `pos` (just past its backtick or the `}` of a substitution) to its
        closing backtick (`template` or `template_tail`) or its next `${` (`template_head` or
        `template_middle`)."""
        text, n = self.text, len(self.text)
        out: list[str] = []
        while pos < n:
            c = text[pos]
            if c == "`":
                self.pos = pos + 1
                done = "template" if kind == "template" else "template_tail"
                return Token(done, "".join(out), start, pos + 1, newline)
            if c == "$" and text.startswith("${", pos):
                self.pos = pos + 2
                self.braces.append(True)
                part = "template_head" if kind == "template" else "template_middle"
                return Token(part, "".join(out), start, pos + 2, newline)
            if c == "\\":
                value, pos = self._escape(pos + 1)
                out.append(value)
                continue
            out.append(c)
            pos += 1
        self.pos = n
        return Token("error", text[start:n], start, n, newline)

    def _regex(self, pos: int, newline: bool) -> Token:
        text, n = self.text, len(self.text)
        start, pos, in_class = pos, pos + 1, False
        while pos < n:
            c = text[pos]
            if c in Lexer.LINE_BREAKS:
                break
            if c == "\\":
                pos += 2
                continue
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                pos += 1
                while pos < n and (text[pos].isalnum() or text[pos] in "_$"):
                    pos += 1
                self.pos = pos
                return Token("regex", text[start:pos], start, pos, newline)
            pos += 1
        self.pos = pos
        return Token("error", text[start:pos], start, pos, newline)

    def _punct(self, pos: int, c: str, newline: bool) -> Token:
        text = self.text
        for candidate in Lexer.PUNCTUATORS.get(c, ()):
            if text.startswith(candidate, pos):
                # `?.` before a digit is a conditional and a number: `a?.5:b`.
                if candidate == "?." and pos + 2 < len(text) and text[pos + 2].isdigit():
                    continue
                self.pos = pos + len(candidate)
                return Token("punct", candidate, pos, self.pos, newline)
        self.pos = pos + 1
        if c == "{":
            self.braces.append(False)
        elif c == "}" and self.braces:
            self.braces.pop()
        kind = "punct" if c in Lexer.SINGLE else "error"
        return Token(kind, c, pos, pos + 1, newline)

    # -- escapes --------------------------------------------------------------

    def _escape(self, pos: int) -> tuple[str, int]:
        """The character a backslash escape at `pos` (just past the backslash) stands for."""
        text, n = self.text, len(self.text)
        if pos >= n:
            return "", pos
        c = text[pos]
        if c == "u":
            return self._unicode_escape(pos + 1)
        if c == "x" and pos + 2 < n:
            digits = text[pos + 1 : pos + 3]
            if all(d in "0123456789abcdefABCDEF" for d in digits):
                return chr(int(digits, 16)), pos + 3
        if c in Lexer.LINE_BREAKS:  # a line continuation
            return "", pos + (2 if text.startswith("\r\n", pos) else 1)
        return Lexer.ESCAPES.get(c, c), pos + 1

    def _unicode_escape(self, pos: int) -> tuple[str, int]:
        """`XXXX` or `{X...}` at `pos` (just past `\\u`)."""
        text, n = self.text, len(self.text)
        if pos < n and text[pos] == "{":
            close = text.find("}", pos, pos + 10)
            digits = text[pos + 1 : close] if close > 0 else ""
            if (
                digits
                and all(d in "0123456789abcdefABCDEF" for d in digits)
                and int(digits, 16) <= 0x10FFFF
            ):
                return chr(int(digits, 16)), close + 1
            return "", pos
        digits = text[pos : pos + 4]
        if len(digits) == 4 and all(d in "0123456789abcdefABCDEF" for d in digits):
            return chr(int(digits, 16)), pos + 4
        return "", pos


__all__ = ["Lexer", "Token"]
