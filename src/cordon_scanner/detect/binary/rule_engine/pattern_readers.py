"""Reading a rule string into terms: a regular expression in the rule language's dialect, and a hex
pattern with its wildcards, jumps and alternatives, each to the same term tree a program is laid out
from.
"""

from __future__ import annotations

import re
from typing import ClassVar

from cordon_scanner.detect.binary.rule_engine.pattern import (
    ANY,
    CLASS,
    COUNT,
    DIGIT,
    EDGE,
    EITHER,
    EMPTY,
    END,
    GAP,
    LIT,
    MASKED,
    NON_DIGIT,
    NON_EDGE,
    NON_SPACE,
    NON_WORD,
    NOT,
    NOT_MASKED,
    PLUS,
    SEQ,
    SPACE,
    STAR,
    START,
    WORD,
    Bytes,
    PatternError,
    Term,
)

#: The largest repeat count a pattern may write, `{n,m}`.
MAX_COUNT = 32767

#: A gap longer than this between two parts of a hex pattern splits it into linked parts.
LINK_GAP = 200


class RegexReader:
    """A rule string's regular expression, as raw bytes, read into a term tree.

    `eager` and `lazy` say which kinds of repeat it holds; a string may not mix them."""

    REPEAT: ClassVar[re.Pattern[bytes]] = re.compile(rb"\{(\d*) *, *(\d*)\}|\{(\d+)\}")
    RANGE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(\\x[0-9A-Fa-f]{2}|\\[^\n]|[^\]\\])-([^\]])", re.DOTALL
    )
    NOT_LITERAL: ClassVar[bytes] = b"\\[()|$.^+*?"
    CONTROL: ClassVar[dict[int, int]] = {ord("n"): 10, ord("t"): 9, ord("r"): 13, ord("f"): 12,
                                         ord("a"): 7}  # fmt: skip

    def __init__(self, source: bytes) -> None:
        self.s, self.i = source, 0
        self.eager = self.lazy = False

    def read(self) -> Term:
        if not self.s:
            raise PatternError("an empty regular expression")
        term = self._either()
        if self.i != len(self.s):
            raise PatternError("a syntax error in a regular expression")
        return term

    def _peek(self) -> int:
        return self.s[self.i] if self.i < len(self.s) else -1

    def _either(self) -> Term:
        term = self._chain()
        while self._peek() == 0x7C:  # |
            self.i += 1
            if self._peek() in (-1, 0x7C, 0x29):
                term = Term(EITHER, term, Term(EMPTY))
            else:
                term = Term(EITHER, term, self._chain())
        return term

    def _chain(self) -> Term:
        items: list[Term] = []
        while self._peek() not in (-1, 0x7C, 0x29):
            items.append(self._repeat())
        if not items:
            raise PatternError("a syntax error in a regular expression")
        return Term(SEQ, *items)

    def _count(self) -> tuple[int, int, int] | None:
        """A `{n}`, `{n,m}`, `{,m}` or `{n,}` here: (lo, hi, length), or None if `{` is a byte."""
        m = RegexReader.REPEAT.match(self.s, self.i)
        if m is None:
            return None
        if m.group(3) is not None:
            n = RegexReader._int(m.group(3))
            if n < 0 or n > MAX_COUNT:
                raise PatternError("a repeat interval too large")
            return n, n, m.end() - m.start()
        lo = RegexReader._int(m.group(1)) if m.group(1) else 0
        hi = RegexReader._int(m.group(2)) if m.group(2) else MAX_COUNT
        if hi > MAX_COUNT:
            raise PatternError("a repeat interval too large")
        if hi < lo or hi < 0 or lo < 0:
            raise PatternError("a bad repeat interval")
        return lo, hi, m.end() - m.start()

    @staticmethod
    def _int(digits: bytes) -> int:
        """Digits as a C int reads them: past 32 bits, the value wraps."""
        v = min(int(digits), 2**63 - 1)
        return ((v + 2**31) % 2**32) - 2**31

    def _repeat(self) -> Term:
        c = self._peek()
        if c == 0x5E:  # ^
            self.i += 1
            return Term(START)
        if c == 0x24:  # $
            self.i += 1
            return Term(END)
        if c == 0x5C and self.s[self.i + 1 : self.i + 2] in (b"b", b"B"):
            self.i += 2
            return Term(EDGE if self.s[self.i - 1] == 0x62 else NON_EDGE)
        term = self._single()
        c = self._peek()
        if c in (0x2A, 0x2B, 0x3F):  # * + ?
            self.i += 1
            eager = not self._lazy_mark()
            if c == 0x2A:
                return Term.counted(STAR, term, 0, 0, eager)
            if c == 0x2B:
                return Term.counted(PLUS, term, 0, 0, eager)
            return self._counted(term, 0, 1, eager)
        if c == 0x7B:
            count = self._count()
            if count is not None:
                self.i += count[2]
                return self._counted(term, count[0], count[1], not self._lazy_mark())
        return term

    def _lazy_mark(self) -> bool:
        lazy = self._peek() == 0x3F
        if lazy:
            self.i += 1
            self.lazy = True
        else:
            self.eager = True
        return lazy

    @staticmethod
    def _counted(term: Term, lo: int, hi: int, eager: bool) -> Term:
        if term.kind == ANY:
            return Term.counted(GAP, None, lo, hi, eager)
        return Term.counted(COUNT, term, lo, hi, eager)

    def _single(self) -> Term:
        c = self._peek()
        if c == 0x28:  # (
            self.i += 1
            term = self._either()
            if self._peek() != 0x29:
                raise PatternError("a syntax error in a regular expression")
            self.i += 1
            return term
        if c == 0x2E:
            self.i += 1
            return Term(ANY, value=0, mask=0)
        if c == 0x5B:
            return self._class()
        if c == 0x5C:
            return self._escape()
        if c in RegexReader.NOT_LITERAL or c == -1:
            raise PatternError("a syntax error in a regular expression")
        if c == 0x7B and self._count() is not None:
            raise PatternError("a repeat with nothing to repeat")
        self.i += 1
        return Term(LIT, value=c)

    def _escape(self) -> Term:
        e = self.s[self.i + 1 : self.i + 2]
        kinds = {b"w": WORD, b"W": NON_WORD, b"s": SPACE, b"S": NON_SPACE, b"d": DIGIT,
                 b"D": NON_DIGIT}  # fmt: skip
        if e in kinds:
            self.i += 2
            return Term(kinds[e])
        if e and e.isdigit():
            raise PatternError("backreferences are not allowed")
        self.i += 1
        return Term(LIT, value=self._escaped())

    def _escaped(self) -> int:
        """The byte an escape stands for, `self.i` just past its backslash."""
        s = self.s
        if self.i >= len(s):
            raise PatternError("an illegal escape sequence")
        e = s[self.i]
        if e == 0x78:  # x
            digits = s[self.i + 1 : self.i + 3]
            if len(digits) < 2 or not all(d in b"0123456789abcdefABCDEF" for d in digits):
                raise PatternError("an illegal escape sequence")
            self.i += 3
            return int(digits, 16)
        self.i += 1
        return RegexReader.CONTROL.get(e, e)

    @staticmethod
    def _escape_value(text: bytes) -> int:
        """The byte a backslash pair (or `\\xHH`) at the start of `text` stands for."""
        if text[1] == 0x78:
            digits = text[2:4]
            if len(digits) < 2 or not all(d in b"0123456789abcdefABCDEF" for d in digits):
                raise PatternError("an illegal escape sequence")
            return int(digits, 16)
        return RegexReader.CONTROL.get(text[1], text[1])

    def _class(self) -> Term:
        s = self.s
        self.i += 1
        bits, negated = 0, False
        if s.startswith(b"^]", self.i):
            negated, bits = True, 1 << 0x5D
            self.i += 2
        elif s.startswith(b"^", self.i):
            negated = True
            self.i += 1
        elif s.startswith(b"]", self.i):
            bits = 1 << 0x5D
            self.i += 1
        sets = {b"w": Bytes.WORD, b"W": Bytes.ALL ^ Bytes.WORD, b"s": Bytes.SPACE,
                b"S": Bytes.ALL ^ Bytes.SPACE, b"d": Bytes.DIGIT,
                b"D": Bytes.ALL ^ Bytes.DIGIT}  # fmt: skip
        while True:
            if self.i >= len(s):
                raise PatternError("a character class without its closing ]")
            c = s[self.i]
            if c == 0x5D:
                self.i += 1
                break
            m = RegexReader.RANGE.match(s, self.i)
            if m is not None:
                first = m.group(1)
                lo = RegexReader._escape_value(first) if first[0] == 0x5C else first[0]
                self.i = m.end()
                hi = m.group(2)[0]
                if hi == 0x5C:
                    hi = self._escaped()
                if hi < lo:
                    raise PatternError("a bad character range")
                bits |= Bytes.span(lo, hi)
                continue
            if c == 0x5C:
                e = s[self.i + 1 : self.i + 2]
                if e in sets:
                    bits |= sets[e]
                    self.i += 2
                    continue
                self.i += 1
                bits |= 1 << self._escaped()
                continue
            if not 32 <= c < 127:
                raise PatternError("a non-ASCII character in a character class")
            bits |= 1 << c
            self.i += 1
        term = Term(CLASS)
        term.bits, term.negated = bits, negated
        return term


class HexReader:
    """A hex pattern, `{ ... }` included, read into a term tree. `plain` is True while it has no
    alternatives: such a pattern runs a position set at a time (`Lanes`)."""

    TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?P<skip>[ \t\r\n]+|/\*.*?\*/|//[^\n]*)"
        r"|(?P<byte>[0-9A-Fa-f]{2})|(?P<hi>[0-9A-Fa-f]\?)|(?P<lo>\?[0-9A-Fa-f])|(?P<any>\?\?)"
        r"|(?P<not>~[0-9A-Fa-f]{2})|(?P<nothi>~[0-9A-Fa-f]\?)|(?P<notlo>~\?[0-9A-Fa-f])"
        r"|(?P<punct>[{}()|\[])",
        re.DOTALL,
    )
    JUMP: ClassVar[re.Pattern[str]] = re.compile(r"[ \t\r\n]*(\d+|-|\])")

    def __init__(self, source: str) -> None:
        self.toks = HexReader._lex(source)
        self.i = 0
        self.nested = 0
        self.plain = True

    @staticmethod
    def _lex(s: str) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        i = 0
        while i < len(s):
            if s.startswith("/*", i) and s.find("*/", i + 2) < 0:
                raise PatternError("an unterminated comment in a hex pattern")
            m = HexReader.TOKEN.match(s, i)
            if m is None:
                c = s[i]
                if c in "0123456789abcdefABCDEF":
                    raise PatternError("an uneven number of digits in a hex pattern")
                if c == "~":
                    raise PatternError("a ~ without a byte in a hex pattern")
                raise PatternError("an invalid character in a hex pattern")
            i = m.end()
            kind = m.lastgroup
            text = m.group()
            if kind == "skip":
                continue
            if kind == "punct":
                out.append((text, 0))
                if text == "[":
                    i = HexReader._jump(s, i, out)
                continue
            assert kind is not None  # noqa: S101 - every alternative is named
            digits = text.lstrip("~")
            value = int(digits.replace("?", "0"), 16)
            mask = 0xF0 if kind in ("hi", "nothi") else 0x0F if kind in ("lo", "notlo") else 0
            out.append((kind, (mask << 8 | value) if mask or kind == "any" else value))
        return out

    @staticmethod
    def _jump(s: str, i: int, out: list[tuple[str, int]]) -> int:
        while True:
            m = HexReader.JUMP.match(s, i)
            if m is None:
                raise PatternError("an invalid character in a hex pattern jump")
            i = m.end()
            text = m.group(1)
            if text == "]":
                out.append(("]", 0))
                return i
            if text == "-":
                out.append(("-", 0))
            else:
                out.append(("num", RegexReader._int(text.encode())))

    def _next(self) -> tuple[str, int]:
        return self.toks[self.i] if self.i < len(self.toks) else ("eof", 0)

    def _want(self, kind: str) -> None:
        if self._next()[0] != kind:
            raise PatternError("a syntax error in a hex pattern")
        self.i += 1

    def read(self) -> Term:
        self._want("{")
        term = self._run()
        self._want("}")
        if self.i != len(self.toks):
            raise PatternError("a syntax error in a hex pattern")
        return term

    def _run(self) -> Term:
        """Bytes and groups with jumps between them; a run starts and ends on a byte or group."""
        items, jumped = [self._token()], False
        while self._next()[0] not in ("}", ")", "|", "eof"):
            jumped = self._next()[0] == "["
            items.append(self._jump_term() if jumped else self._token())
        if jumped:
            raise PatternError("a syntax error in a hex pattern")
        if len(items) == 1:
            return items[0]
        return Term(SEQ, *items)

    def _token(self) -> Term:
        kind, value = self._next()
        if kind == "(":
            self.i += 1
            self.nested += 1
            term = self._run()
            while self._next()[0] == "|":
                self.i += 1
                self.plain = False
                term = Term(EITHER, term, self._run())
            self._want(")")
            self.nested -= 1
            return term
        self.i += 1
        if kind == "byte":
            return Term(LIT, value=value)
        if kind == "not":
            return Term(NOT, value=value)
        if kind == "any":
            return Term(ANY, value=0, mask=0)
        if kind in ("hi", "lo"):
            return Term(MASKED, value=value & 0xFF, mask=value >> 8)
        if kind in ("nothi", "notlo"):
            return Term(NOT_MASKED, value=value & 0xFF, mask=value >> 8)
        raise PatternError("a syntax error in a hex pattern")

    def _jump_term(self) -> Term:
        self._want("[")
        kind, lo = self._next()
        if kind == "-":
            self.i += 1
            self._want("]")
            return self._gap(0, None)
        if kind != "num":
            raise PatternError("a syntax error in a hex pattern")
        self.i += 1
        if self._next()[0] == "]":
            self.i += 1
            if lo <= 0:
                raise PatternError("an invalid jump length")
            if self.nested and lo > LINK_GAP:
                raise PatternError(f"jumps over {LINK_GAP} are not allowed inside alternatives")
            if lo == 1:
                term = Term(MASKED, value=0, mask=0)
                term.eager = False
                return term
            return self._gap(lo, lo)
        self._want("-")
        kind, hi = self._next()
        if kind == "]":
            self.i += 1
            if lo < 0:
                raise PatternError("an invalid negative jump length")
            return self._gap(lo, None)
        if kind != "num":
            raise PatternError("a syntax error in a hex pattern")
        self.i += 1
        self._want("]")
        if self.nested and (lo > LINK_GAP or hi > LINK_GAP):
            raise PatternError(f"jumps over {LINK_GAP} are not allowed inside alternatives")
        if lo < 0 or hi < 0:
            raise PatternError("an invalid negative jump length")
        if lo > hi:
            raise PatternError("an invalid jump range")
        return self._gap(lo, hi)

    def _gap(self, lo: int, hi: int | None) -> Term:
        if hi is None:
            if self.nested:
                raise PatternError("unbounded jumps are not allowed inside alternatives")
            hi = 2**31 - 1
        return Term.counted(GAP, None, lo, hi, False)


__all__ = ["LINK_GAP", "MAX_COUNT", "HexReader", "RegexReader"]
