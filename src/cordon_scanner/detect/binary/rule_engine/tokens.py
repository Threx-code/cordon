"""A rule file read into tokens: identifiers, keywords, numbers with their size suffixes, quoted text,
regular expressions and hex strings, each with the line it is on, so the grammar reads a stream and
an error (RuleError) can say where.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar


class RuleError(ValueError):
    """The rules do not compile."""


INT64_MAX = 2**63 - 1


@dataclass(slots=True)
class Token:
    #: word, int, float, text, hex, regex, sigil ($a, #a, @a, !a), mark (punctuation), end
    kind: str
    value: Any
    line: int
    #: The included files this token was read through, outermost first (empty: the given text).
    chain: tuple[Path, ...] = ()


class Includes:
    """Where `include` may read from: files under one directory, the rule collection's root.

    A name is read relative to the file that includes it (the top file's directory for the given
    text), as the reference reads it. Refused: an absolute name, a file outside the root once
    links are resolved, a file already being included (a cycle), nesting deeper than
    `MAX_DEPTH`, and more bytes in all than `max_bytes`."""

    MAX_DEPTH: ClassVar[int] = 32

    def __init__(self, root: Path, top: Path | None = None, max_bytes: int = 16 << 20) -> None:
        self.root = root.resolve()
        self.top = top.resolve() if top is not None else None
        self.left = max_bytes

    def tokens(self, name: str, chain: tuple[Path, ...], line: int) -> list[Token]:
        """The tokens of the file `name` names, from a directive on `line` of the last file in
        `chain`; each carries the chain it was read through."""

        def refuse(why: str) -> RuleError:
            return RuleError(f"line {line}: include {name!r}: {why}")

        if Path(name).is_absolute():
            raise refuse("an absolute path")
        including = chain[-1] if chain else self.top
        target = ((including.parent if including else self.root) / name).resolve()
        if not target.is_relative_to(self.root):
            raise refuse("outside the rule collection")
        if target in chain or target == self.top:
            raise refuse("an include cycle")
        if len(chain) >= Includes.MAX_DEPTH:
            raise refuse(f"includes nested deeper than {Includes.MAX_DEPTH}")
        if not target.is_file():
            raise refuse("no such file")
        size = target.stat().st_size
        if size > self.left:
            raise refuse("the included rules are over the size limit")
        self.left -= size
        where = target.relative_to(self.root)
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise refuse(f"unreadable: {exc.strerror}") from exc
        try:
            toks = Tokens(text).all()[:-1]
        except RuleError as exc:
            raise RuleError(f"{where}: {exc}") from exc
        for tok in toks:
            tok.chain = (*chain, target)
        return toks


class Tokens:
    """Rule text as tokens, with its line numbers."""

    #: Punctuation, longest first where one begins another.
    MARKS: ClassVar[tuple[str, ...]] = (
        "..", "<<", ">>", "<=", ">=", "==", "!=", "(", ")", "{", "}", "[", "]", ":", ",", "=",
        "+", "-", "*", "\\", "%", "&", "|", "^", "~", "<", ">", ".",
    )  # fmt: skip
    #: What may sit between the braces of a hex string, besides comments.
    HEX_BODY: ClassVar[frozenset[str]] = frozenset("0123456789abcdefABCDEF -|~?[]()\n\r\t")
    ESCAPES: ClassVar[dict[str, int]] = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34}
    NUMBER: ClassVar[re.Pattern[str]] = re.compile(
        r"0x[0-9a-fA-F]+|0o[0-7]+|\d+\.\d+|\d+(?:KB|MB)?"
    )
    WORD: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    SIGIL: ClassVar[re.Pattern[str]] = re.compile(r"[$#@!][A-Za-z0-9_]*\*?")
    FLAGS: ClassVar[re.Pattern[str]] = re.compile(r"[is]*")
    HEX2: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{2}")

    def __init__(self, text: str) -> None:
        self.text, self.at, self.line = text, 0, 1

    def fail(self, what: str) -> RuleError:
        return RuleError(f"line {self.line}: {what}")

    def all(self) -> list[Token]:
        out: list[Token] = []
        while self._blank():
            out.append(self._next())
        out.append(Token("end", None, self.line))
        return out

    def _blank(self) -> bool:
        """Skips white space and comments; whether anything is left."""
        t, n = self.text, len(self.text)
        while self.at < n:
            c = t[self.at]
            if c == "\n":
                self.line += 1
                self.at += 1
            elif c in " \t\r":
                self.at += 1
            elif t.startswith("//", self.at):
                close = t.find("\n", self.at)
                self.at = n if close < 0 else close
            elif t.startswith("/*", self.at):
                close = t.find("*/", self.at + 2)
                if close < 0:
                    raise self.fail("an unterminated comment")
                self.line += t.count("\n", self.at, close)
                self.at = close + 2
            else:
                return True
        return False

    def _next(self) -> Token:
        t, start, line = self.text, self.at, self.line
        c = t[start]
        if c == '"':
            return Token("text", self._text(), line)
        if c == "{":
            close = Tokens.hex_close(t, start)
            if close is not None:
                body = t[start + 1 : close - 1]
                self.line += body.count("\n")
                self.at = close
                return Token("hex", body, line)
        if c == "/":
            # comments are already skipped and division is written `\`, so `/` opens a regex
            return Token("regex", self._regex(), line)
        after = t[start + 1 : start + 2]
        if c in "$#@" or (c == "!" and after != "="):
            m = Tokens.SIGIL.match(t, start)
            assert m is not None  # noqa: S101 - its first character matched just above
            self.at = m.end()
            return Token("sigil", m.group(), line)
        m = Tokens.NUMBER.match(t, start)
        if m:
            self.at = m.end()
            return Tokens._number(m.group(), line, self)
        m = Tokens.WORD.match(t, start)
        if m:
            self.at = m.end()
            return Token("word", m.group(), line)
        for mark in Tokens.MARKS:
            if t.startswith(mark, start):
                self.at = start + len(mark)
                return Token("mark", mark, line)
        raise self.fail(f"an unexpected character {c!r}")

    @staticmethod
    def _number(s: str, line: int, where: Tokens) -> Token:
        if "." in s:
            return Token("float", float(s), line)
        scale = {"KB": 1024, "MB": 1024 * 1024}.get(s[-2:], 1)
        digits = s[:-2] if scale > 1 else s
        value = (int(digits, 0) if digits[:2] in ("0x", "0o") else int(digits)) * scale
        if value > INT64_MAX:
            raise where.fail(f"an integer {s} beyond 64 bits")
        return Token("int", value, line)

    @staticmethod
    def hex_close(t: str, start: int) -> int | None:
        """Just past the `}` that closes a hex string opening at `start`, or None when the brace
        opens something else. A hex string holds hex digits, its punctuation, white space and
        comments (`//` ones ended by a newline), at least one of them, up to the first `}`
        outside a comment."""
        i, n = start + 1, len(t)
        while i < n:
            c = t[i]
            if c == "}":
                return i + 1 if i > start + 1 else None
            if c in Tokens.HEX_BODY:
                i += 1
                continue
            for opener, closer, past in (("/*", "*/", 2), ("//", "\n", 1)):
                if t.startswith(opener, i):
                    close = t.find(closer, i + 2)
                    if close < 0:
                        return None
                    i = close + past
                    break
            else:
                return None
        return None

    def _text(self) -> bytes:
        t, out = self.text, bytearray()
        self.at += 1
        while True:
            if self.at >= len(t) or t[self.at] == "\n":
                raise self.fail("an unterminated string")
            c = t[self.at]
            if c == '"':
                self.at += 1
                return bytes(out)
            if c != "\\":
                out += c.encode("utf-8")
                self.at += 1
                continue
            e = t[self.at + 1 : self.at + 2]
            if e == "x":
                digits = t[self.at + 2 : self.at + 4]
                if not Tokens.HEX2.fullmatch(digits):
                    raise self.fail("a \\x escape without two hex digits")
                out.append(int(digits, 16))
                self.at += 4
            elif e in Tokens.ESCAPES:
                out.append(Tokens.ESCAPES[e])
                self.at += 2
            else:
                raise self.fail(f"an unknown escape \\{e}")

    def _regex(self) -> tuple[str, str]:
        t, parts = self.text, []
        self.at += 1
        while True:
            if self.at >= len(t) or t[self.at] == "\n":
                raise self.fail("an unterminated regular expression")
            c = t[self.at]
            if c == "\\" and self.at + 1 < len(t):
                parts.append(t[self.at : self.at + 2])
                self.at += 2
            elif c == "/":
                self.at += 1
                break
            else:
                parts.append(c)
                self.at += 1
        m = Tokens.FLAGS.match(t, self.at)
        flags = m.group() if m else ""
        self.at += len(flags)
        return "".join(parts), flags


__all__ = ["INT64_MAX", "RuleError", "Token", "Tokens"]
