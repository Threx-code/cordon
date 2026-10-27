"""cordon-rule patterns: the regular expressions and hex patterns of a rule's strings.

A pattern is read into a tree of `Term`s (`RegexReader`, `HexReader`). `Program` lays a tree out
as instructions twice -- once to be read forwards, once backwards -- and records, for every term,
where the forward layout enters it and where the backward layout resumes after it, so a search
may begin at any literal run inside a pattern and grow the match both ways from there. `Threads`
runs a layout over the data from one position with its threads in priority order; `Lanes` runs
the layouts of plain hex patterns (no alternatives) a position set at a time. `Anchors` chooses
the short literal runs a search looks for before it runs anything.

Every bound is fixed: a run reads at most `REACH` bytes either way, holds at most `MAX_THREADS`
threads, and a layout's jumps stay within `MAX_JUMP` bytes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, ClassVar

#: How far a single run may read from where it starts, in either direction.
REACH = 4096
#: The most threads one run may hold at once.
MAX_THREADS = 1024
#: The largest repeat count a pattern may write, `{n,m}`.
MAX_COUNT = 32767
#: The longest a jump in a layout may be, in layout bytes, either way.
MAX_JUMP = 32767
#: The most forks one layout may contain.
MAX_FORKS = 128
#: A gap longer than this between two parts of a hex pattern splits it into linked parts.
LINK_GAP = 200
#: An anchor is at most this many bytes.
ANCHOR = 4
#: The best score an anchor can have.
TOP_SCORE = 255


class PatternError(ValueError):
    """A pattern that does not read, or cannot be laid out."""


class RunError(RuntimeError):
    """A run that went past one of its fixed bounds."""


# -- terms --------------------------------------------------------------------

# Term kinds. Byte terms first: these are the ones an anchor can be made of.
LIT, MASKED, ANY = 1, 2, 3
NOT, NOT_MASKED, CLASS = 4, 5, 6
WORD, NON_WORD, SPACE, NON_SPACE, DIGIT, NON_DIGIT = 7, 8, 9, 10, 11, 12
START, END, EDGE, NON_EDGE = 13, 14, 15, 16
SEQ, EITHER, STAR, PLUS, COUNT, GAP, EMPTY = 17, 18, 19, 20, 21, 22, 23


class Term:
    __slots__ = ("back", "bits", "eager", "fwd", "hi", "kids", "kind", "lo", "mask", "negated",
                 "value")  # fmt: skip

    def __init__(self, kind: int, *kids: Term, value: int = 0, mask: int = 0xFF) -> None:
        self.kind = kind
        self.kids: list[Term] = list(kids)
        self.value, self.mask = value, mask
        self.lo = self.hi = 0
        self.eager = True  # a repeat that prefers more; False prefers fewer
        self.bits, self.negated = 0, False  # CLASS: one bit per byte value
        self.fwd: int | None = None  # where the forward layout enters this term
        self.back: int | None = None  # where the backward layout resumes after it

    @staticmethod
    def counted(kind: int, kid: Term | None, lo: int, hi: int, eager: bool) -> Term:
        t = Term(kind) if kid is None else Term(kind, kid)
        t.lo, t.hi, t.eager = lo, hi, eager
        return t


class Bytes:
    """Byte classes as 256-bit masks, and the case tables, ASCII only."""

    WORD: ClassVar[int] = sum(1 << c for c in b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
                              b"abcdefghijklmnopqrstuvwxyz")  # fmt: skip
    SPACE: ClassVar[int] = sum(1 << c for c in b"\t\n\x0b\x0c\r ")
    DIGIT: ClassVar[int] = sum(1 << c for c in b"0123456789")
    ALL: ClassVar[int] = (1 << 256) - 1
    LOWER: ClassVar[bytes] = bytes(c + 32 if 65 <= c <= 90 else c for c in range(256))
    SWAP: ClassVar[bytes] = bytes(
        c + 32 if 65 <= c <= 90 else c - 32 if 97 <= c <= 122 else c for c in range(256)
    )
    ALNUM: ClassVar[frozenset[int]] = frozenset(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                b"abcdefghijklmnopqrstuvwxyz")  # fmt: skip

    @staticmethod
    def span(lo: int, hi: int) -> int:
        return ((1 << (hi + 1)) - 1) ^ ((1 << lo) - 1)


# -- reading a regular expression ----------------------------------------------


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


# -- reading a hex pattern ---------------------------------------------------


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


# -- layouts ------------------------------------------------------------------


class Op:
    """Instruction codes. A layout is a list of tuples, each led by one of these."""

    # those that read a byte
    BYTE, NOT_BYTE, MASK, NOT_MASK, ANY, CLASS = 1, 2, 3, 4, 5, 6
    WORD, NON_WORD, SPACE, NON_SPACE, DIGIT, NON_DIGIT = 7, 8, 9, 10, 11, 12
    SKIP = 13  # skip lo..hi bytes, counting in the thread
    # those that test without reading
    START, END, EDGE, NON_EDGE = 14, 15, 16, 17
    DONE = 18
    # those that only move threads
    FORK, GOTO, ENTER, AGAIN = 19, 20, 21, 22

    READS: ClassVar[frozenset[int]] = frozenset(range(1, 14))
    TESTS: ClassVar[frozenset[int]] = frozenset(range(14, 18))
    #: The bytes each takes in a layout: the jump limits are counted in these.
    SIZE: ClassVar[dict[int, int]] = {BYTE: 2, NOT_BYTE: 2, MASK: 3, NOT_MASK: 3, CLASS: 34,
                                      SKIP: 5, FORK: 4, GOTO: 3, ENTER: 9, AGAIN: 9}  # fmt: skip


#: The instruction each single-instruction term lays out as.
TERM_OPS = {ANY: Op.ANY, WORD: Op.WORD, NON_WORD: Op.NON_WORD, SPACE: Op.SPACE,
            NON_SPACE: Op.NON_SPACE, DIGIT: Op.DIGIT, NON_DIGIT: Op.NON_DIGIT, START: Op.START,
            END: Op.END, EDGE: Op.EDGE, NON_EDGE: Op.NON_EDGE}  # fmt: skip


class Program:
    """A term tree laid out to be read one way. Every term records where the forward layout
    enters it (`Term.fwd`) or where the backward layout resumes after it (`Term.back`)."""

    def __init__(self, root: Term, backwards: bool) -> None:
        self.ops: list[tuple[int, ...]] = []
        self.at: list[int] = []  # each instruction's byte address
        self.size = 0
        self.forks = 0
        self.backwards = backwards
        self.entry = self._lay(root, True, True)
        self._put((Op.DONE,))

    def _put(self, op: tuple[int, ...]) -> int:
        self.ops.append(op)
        self.at.append(self.size)
        self.size += Op.SIZE.get(op[0], 1)
        return len(self.ops) - 1

    def _fork(self, prefer_target: bool) -> int:
        if self.forks == MAX_FORKS:
            raise PatternError("a pattern too complex to lay out")
        self.forks += 1
        return self._put((Op.FORK, self.forks - 1, -1, int(prefer_target)))

    def _aim(self, at: int, target: int) -> None:
        op = self.ops[at]
        self.ops[at] = (*op[:-2], target, op[-1]) if op[0] == Op.FORK else (Op.GOTO, target)

    def _reach(self, distance: int) -> None:
        if distance > MAX_JUMP or distance < -MAX_JUMP - 1:
            raise PatternError("a pattern too large to lay out")

    def _lay(self, t: Term, fwd: bool, back: bool) -> int | None:
        entry: int | None = None
        k = t.kind
        if k == LIT:
            entry = self._put((Op.BYTE, t.value))
        elif k == NOT:
            entry = self._put((Op.NOT_BYTE, t.value))
        elif k == MASKED:
            entry = self._put((Op.MASK, t.mask, t.value))
        elif k == NOT_MASKED:
            entry = self._put((Op.NOT_MASK, t.mask, t.value))
        elif k == CLASS:
            entry = self._put((Op.CLASS, t.bits, int(t.negated)))
        elif k in TERM_OPS:
            entry = self._put((TERM_OPS[k],))
        elif k == GAP:
            entry = self._put((Op.SKIP, t.lo & 0xFFFF, t.hi & 0xFFFF, int(t.eager)))
        elif k == SEQ:
            kids = t.kids[::-1] if self.backwards else t.kids
            entry = self._lay(kids[0], fwd, back)
            for kid in kids[1:]:
                self._lay(kid, fwd, back)
        elif k == PLUS:
            entry = self._lay(t.kids[0], fwd, back)
            if entry is not None:  # a repeat of something that lays out nothing is nothing
                self._reach(self.size - self.at[entry])
                self._aim(self._fork(t.eager), entry)
        elif k == STAR:
            entry = self._fork(not t.eager)
            self._lay(t.kids[0], fwd, back)
            self._reach(self.size - self.at[entry])
            self._aim(self._put((Op.GOTO, -1)), entry)
            self._reach(self.size - self.at[entry])
            self._aim(entry, len(self.ops))
        elif k == EITHER:
            entry = self._fork(False)
            self._lay(t.kids[0], fwd, back)
            jump = self._put((Op.GOTO, -1))
            self._reach(self.size - self.at[entry])
            self._aim(entry, len(self.ops))
            self._lay(t.kids[1], fwd, back)
            self._reach(self.size - self.at[jump])
            self._aim(jump, len(self.ops))
        elif k == COUNT:
            entry = self._lay_count(t, fwd, back)
        if self.backwards:
            if back:
                t.back = len(self.ops)
        elif fwd:
            t.fwd = entry
        return entry

    def _lay_count(self, t: Term, fwd: bool, back: bool) -> int | None:
        """`kid{lo,hi}`: the first copy laid out on its own (so an anchor's forward run starts
        outside any loop), a counted loop for the middle copies, and the last copy behind a fork
        when it is optional (so the backward run resumes outside the loop too)."""
        lo, hi, kid = t.lo, t.hi, t.kids[0]
        first = lo > 0
        loop = hi > lo + 1 or hi > 2
        optional = hi > lo
        last = hi > lo or hi > 1
        entry: int | None = None
        if first:
            entry = self._lay(kid, fwd, back)
        if loop:
            a, b = lo, hi
            if first:
                a, b = a - 1, b - 1
            if optional:
                b -= 1
            else:
                a, b = a - 1, b - 1
            start = self._put((Op.ENTER, a, b, -1, int(t.eager)))
            if not first:
                entry = start
            body = len(self.ops)
            self._lay(kid, False, False)
            if len(self.ops) == body:  # a counted loop with nothing in it cannot be laid out
                raise PatternError("a pattern too large to lay out")
            self._put((Op.AGAIN, a, b, body, int(t.eager)))
            self.ops[start] = (Op.ENTER, a, b, len(self.ops), int(t.eager))
        fork = self._fork(not t.eager) if optional else -1
        if last:
            e = self._lay(kid, fwd and not first, back)
            if not first and not loop:
                entry = e
        if optional:
            self._reach(self.size - self.at[fork])
            self._aim(fork, len(self.ops))
        return entry


# -- running a layout --------------------------------------------------------


class Memo:
    """The steps one layout has taken in one run mode: thread lists numbered as they are first
    seen, and for each (list, byte, surroundings) the list it led to and the matches it reached.
    Past `Memo.LIMIT` steps it starts afresh, so its size is bounded whatever the data."""

    LIMIT: ClassVar[int] = 1 << 16

    def __init__(self) -> None:
        self.states: list[tuple[tuple[Any, ...], ...]] = [()]
        self.numbers: dict[tuple[tuple[Any, ...], ...], int] = {(): 0}
        self.steps: dict[tuple[Any, ...], tuple[int, int]] = {}
        #: The thread list each entry point settles to.
        self.starts: dict[int, int] = {}
        #: For a thread list, the bytes that lead back to it with no match whatever surrounds
        #: them (a translate table: 0 for those bytes, 1 for the rest), or None for none.
        self.loops: dict[int, bytes | None] = {}
        #: For an entry point, the first bytes that can lead anywhere (None: any byte can).
        self.firsts: dict[int, frozenset[int] | None] = {}
        #: For a thread list, whether a thread in it is at a position test: only then does a step
        #: from it depend on what surrounds the byte it reads.
        self.testing: dict[int, bool] = {}
        #: For an entry point, a pattern finding where a run from it can do anything (`prefilter`).
        self.filters: dict[int, re.Pattern[bytes] | None] = {}

    def state(self, keys: tuple[tuple[Any, ...], ...]) -> int:
        number = self.numbers.get(keys)
        if number is None:
            number = self.numbers[keys] = len(self.states)
            self.states.append(keys)
        return number

    def remember(self, key: tuple[Any, ...], went: tuple[int, int]) -> None:
        if len(self.steps) >= Memo.LIMIT:
            self.steps.clear()
        self.steps[key] = went


class Threads:
    """Runs a layout from one position, its threads in priority order.

    A thread is `[pc, counts, skipped]`: where it is, the counts of the counted loops it is in,
    and how many bytes it has skipped in a `SKIP`. `found` is the match length the run ends
    with (-1 for none); with `every`, each match is handed to it as it is reached instead."""

    def __init__(
        self, ops: list[tuple[int, ...]], memo: dict[tuple[bool, ...], Memo] | None = None
    ) -> None:
        self.ops = ops
        self.live = 0
        #: Steps already worked out, by run mode; kept by whoever owns the layout.
        self.memo: dict[tuple[bool, ...], Memo] = {} if memo is None else memo
        #: Whether this run reports each match rather than letting the first end the step.
        self.every = False
        self.flags = (False, False)  # nocase, dotall of the current run

    def _new(self, pc: int, counts: tuple[int, ...] = (), skipped: int = -1) -> list[Any]:
        if self.live >= MAX_THREADS:
            raise RunError("a pattern needed too many threads")
        self.live += 1
        return [pc, counts, skipped]

    def _settle(self, first: list[Any]) -> list[list[Any]]:
        """`first` and the threads it forks, moved on to their next byte read or test, in
        priority order. A fork reached twice in one settling ends the later thread there."""
        ops = self.ops
        out: list[list[Any]] = []
        queue = [first]
        forked: set[int] = set()
        while queue:
            t = queue[0]
            op = ops[t[0]]
            code = op[0]
            if code == Op.FORK:
                if op[1] in forked:
                    self.live -= 1
                    queue.pop(0)
                    continue
                forked.add(op[1])
                other = self._new(t[0], t[1], t[2])
                if op[3]:
                    t[0], other[0] = op[2], t[0] + 1
                else:
                    t[0], other[0] = t[0] + 1, op[2]
                queue.insert(1, other)
            elif code == Op.GOTO:
                t[0] = op[1]
            elif code == Op.ENTER:
                _, lo, _hi, out_to, eager = op
                if lo == 0:
                    other = self._new(t[0], t[1], t[2])
                    inside, outside = (t, other) if eager else (other, t)
                    outside[0] = out_to
                    inside[0] += 1
                    inside[1] = (*inside[1], 0)
                    queue.insert(1, other)
                else:
                    t[0] += 1
                    t[1] = (*t[1], 0)
            elif code == Op.AGAIN:
                _, lo, hi, body, eager = op
                n = t[1][-1] + 1
                t[1] = (*t[1][:-1], n)
                if n < lo:
                    t[0] = body
                    continue
                if n < hi:
                    other = self._new(t[0], t[1], t[2])
                    again, leave = (t, other) if eager else (other, t)
                    again[0] = body
                    leave[0] += 1
                    leave[1] = leave[1][:-1]
                    queue.insert(1, other)
                else:
                    t[0] += 1
                    t[1] = t[1][:-1]
            elif code == Op.SKIP:
                _, lo, hi, eager = op
                if t[2] == -1:
                    t[2] = 0
                if t[2] < lo:
                    t[2] += 1
                    out.append(t)
                    queue.pop(0)
                elif t[2] < hi:
                    other = self._new(t[0], t[1], t[2])
                    spin, go = (t, other) if eager else (other, t)
                    spin[2] += 1
                    go[0] += 1
                    go[2] = -1
                    went = self._settle(go)
                    out.extend([t, *went] if eager else [*went, other])
                    queue.pop(0)
                else:
                    t[0] += 1
                    t[2] = -1
            else:
                out.append(t)
                queue.pop(0)
        return out

    AROUND: ClassVar[list[tuple[bool, bool, bool, bool]]] = [
        (a, b, c, d) for a in (False, True) for b in (False, True) for c in (False, True)
        for d in (False, True)
    ]  # fmt: skip
    QUIET: ClassVar[tuple[bool, bool, bool, bool]] = (False, False, False, False)

    def _memo(self, backwards: bool, wide: bool, nocase: bool, dotall: bool, every: bool) -> Memo:
        mode = (backwards, wide, nocase, dotall, every)
        memo = self.memo.get(mode)
        if memo is None or len(memo.states) > Memo.LIMIT:
            memo = self.memo[mode] = Memo()
        self.flags = (nocase, dotall)
        self.every = every
        return memo

    def _start(self, memo: Memo, entry: int) -> int:
        state = memo.starts.get(entry)
        if state is None:
            self.live = 0
            state = memo.starts[entry] = memo.state(Threads._keys(self._settle(self._new(entry))))
        return state

    def _testing(self, memo: Memo, state: int) -> bool:
        tested = memo.testing.get(state)
        if tested is None:
            tested = memo.testing[state] = any(
                self.ops[k[0]][0] in Op.TESTS for k in memo.states[state]
            )
        return tested

    def _step(
        self, memo: Memo, state: int, c: int, low: bool, around: tuple[bool, bool, bool, bool]
    ) -> tuple[int, int]:
        key: tuple[Any, ...] = (
            (state, c, low, around) if self._testing(memo, state) else (state, c, low)
        )
        went = memo.steps.get(key)
        if went is None:
            threads = [list(k) for k in memo.states[state]]
            self.live = len(threads)
            after, hits = self._pass(threads, c, low, around, *self.flags)
            went = (memo.state(Threads._keys(after)), hits)
            memo.remember(key, went)
        return went

    def _loop(self, memo: Memo, state: int) -> bytes | None:
        """The bytes that bring `state` back to itself with no match, in every surrounding."""
        if state in memo.loops:
            return memo.loops[state]
        arounds = Threads.AROUND if self._testing(memo, state) else [Threads.QUIET]
        table = bytearray(b"\x01" * 256)
        for c in range(256):
            try:
                steady = all(self._step(memo, state, c, True, a) == (state, 0) for a in arounds)
            except RunError:  # a byte this probe cannot settle is simply not skipped
                steady = False
            if steady:
                table[c] = 0
        loop = bytes(table) if 0 in table else None
        memo.loops[state] = loop
        return loop

    def first_reads(
        self, entry: int, *, wide: bool = False, nocase: bool = False, dotall: bool = False
    ) -> frozenset[int] | None:
        """The bytes a forward run from `entry` can do anything at all with when it reads them
        first; None when it can do something whatever comes first (an empty match, a test)."""
        memo = self._memo(False, wide, nocase, dotall, False)
        if entry in memo.firsts:
            return memo.firsts[entry]
        start = self._start(memo, entry)
        arounds = Threads.AROUND if self._testing(memo, start) else [Threads.QUIET]
        lows = (True, False) if wide else (True,)
        live: set[int] | None = set()
        for c in range(-1, 256):
            try:
                moves = any(
                    self._step(memo, start, c, low, a) != (0, 0) for low in lows for a in arounds
                )
            except RunError:  # the real run meets the same bound when it reads this byte
                moves = True
            if moves:
                if c < 0:
                    live = None
                    break
                assert live is not None  # noqa: S101 - set until a -1 read is found live
                live.add(c)
        firsts = None if live is None else frozenset(live)
        memo.firsts[entry] = firsts
        return firsts

    def prefilter(
        self, entry: int, *, nocase: bool = False, dotall: bool = False, depth: int = 3
    ) -> re.Pattern[bytes] | None:
        """A pattern that matches (zero-width) at every position a one-byte-wide forward run from
        `entry` can do anything at: the positions it misses are ones where every thread dies
        within `depth` bytes having matched nothing. None when no such pattern helps (the layout
        tests positions, or the first step already decides nothing)."""
        memo = self._memo(False, False, nocase, dotall, False)
        if entry not in memo.filters:
            body = self._ahead(memo, self._start(memo, entry), depth)
            memo.filters[entry] = None if body is None else re.compile(b"(?=" + body + b")")
        return memo.filters[entry]

    def _ahead(self, memo: Memo, state: int, depth: int, chain: int = 64) -> bytes | None:
        """The bytes from `state` that keep some thread alive (or reach a match on the way), as a
        regular expression; None for "any bytes at all". It looks `depth` steps ahead where the
        bytes lead to different thread lists, and up to `chain` steps along a single path."""
        if depth == 0 or chain == 0 or self._testing(memo, state):
            return None
        try:
            if self._step(memo, state, -1, False, Threads.QUIET) != (0, 0):
                return None
            leads: dict[int, list[int]] = {}  # next thread list -> the bytes that lead to it
            matched: list[int] = []
            for c in range(256):
                nxt, hits = self._step(memo, state, c, True, Threads.QUIET)
                if hits:
                    matched.append(c)
                elif nxt:
                    leads.setdefault(nxt, []).append(c)
            if len(leads) > 16:
                return None
            single = len(leads) == 1 and not matched
            groups: dict[bytes | None, list[int]] = {}
            if matched:
                groups[None] = matched
            for nxt, cs in leads.items():
                rest = self._ahead(memo, nxt, depth if single else depth - 1, chain - 1)
                groups.setdefault(rest, []).extend(cs)
        except RunError:
            return None
        if not groups:
            return b"(?!)"
        parts = []
        for rest, cs in groups.items():
            members = b"".join(re.escape(bytes([c])) for c in sorted(cs))
            parts.append(b"[" + members + b"]" + (b"" if rest is None else rest))
        body = b"(?:" + b"|".join(parts) + b")"
        return None if len(body) > 1 << 16 else body

    def run(self, entry: int, data: bytes, at: int, *, backwards: bool = False,
            wide: bool = False, nocase: bool = False, dotall: bool = False,
            every: Callable[[int, int], None] | None = None, scan: bool = False,
            masks: dict[bytes, bytes] | None = None) -> int:  # fmt: skip
        """Runs from `at`, forwards or backwards; returns the match length (-1 for none), or,
        with `every`, calls it with (start, length) at each match. With `scan`, a new thread
        starts at every further position too, as when testing whether a text matches.

        A step is decided by the threads it starts with, the byte read and -- when the layout
        tests positions -- what surrounds it; each such step is worked out once (`_pass`) and
        then looked up. A list of threads that a run of bytes leaves unchanged is carried past
        the whole run at once (`masks` holds the data translated for each such set of bytes)."""
        n = len(data)
        width = 2 if wide else 1
        step = -width if backwards else width
        reach = min(at if backwards else n - at, REACH)
        reach -= reach % width
        pos = at - width if backwards else at
        done = 0
        found = -1
        memo = self._memo(backwards, wide, nocase, dotall, every is not None)
        state = self._start(memo, entry)
        quiet = Threads.QUIET
        steady = 0
        while state:
            if done < reach:
                c = data[pos]
                low = not wide or data[pos + 1] == 0
            else:
                c, low = -1, False
            if self._testing(memo, state):
                around = (
                    (at <= done) if backwards else (at == 0 and done == 0),
                    not backwards and n - at <= done,
                    self._word(data, pos - step, width),
                    self._word(data, pos, width),
                )
            else:
                around = quiet
            nxt, hits = self._step(memo, state, c, low, around)
            if hits:
                found = done
                if every is not None:
                    for _ in range(hits):
                        every(pos + width if backwards else at, done)
            pos += step
            done += width
            if scan and done < reach:
                threads = [list(k) for k in memo.states[nxt]]
                self.live = len(threads)
                threads.extend(self._settle(self._new(entry)))
                nxt = memo.state(Threads._keys(threads))
            elif nxt == state and not hits and not wide and masks is not None:
                steady += 1
                if steady >= 4 and done < reach:
                    loop = self._loop(memo, state)
                    if loop is not None:
                        mask = masks.get(loop)
                        if mask is None:
                            mask = masks[loop] = data.translate(loop)
                        if backwards:
                            stop = mask.rfind(b"\x01", at - reach, pos + 1)
                            moved = pos - stop if stop >= 0 else pos - (at - reach) + 1
                        else:
                            stop = mask.find(b"\x01", pos, at + reach)
                            moved = (stop if stop >= 0 else at + reach) - pos
                        pos += moved if not backwards else -moved
                        done += moved
            else:
                steady = 0
            state = nxt
        return found

    @staticmethod
    def _keys(threads: list[list[Any]]) -> tuple[tuple[Any, ...], ...]:
        """The threads as a step sees them: the later of two identical threads dropped."""
        return tuple(dict.fromkeys((t[0], t[1], t[2]) for t in threads))

    def _pass(
        self, threads: list[list[Any]], c: int, low: bool, around: tuple[bool, bool, bool, bool],
        nocase: bool, dotall: bool,
    ) -> tuple[list[list[Any]], int]:  # fmt: skip
        """One step over `threads` (in priority order): each reads byte `c` (-1 past the reach;
        `low` False when a wide character's upper byte is not zero) or tests the position.
        Returns the threads for the next step and how many matches the step reached; without
        a caller hearing every match, the first match ends every thread after it."""
        ops = self.ops
        lower = Bytes.LOWER
        start_ok, end_ok, before, here = around
        hits = 0
        tested: set[tuple[Any, ...]] = set()
        i = 0
        while i < len(threads):
            t = threads[i]
            op = ops[t[0]]
            code = op[0]
            if code in Op.READS:
                if c < 0 or not low:
                    ok = False
                elif code == Op.BYTE:
                    ok = lower[c] == lower[op[1]] if nocase else c == op[1]
                elif code == Op.ANY or code == Op.SKIP:
                    ok = dotall or c != 10
                elif code == Op.CLASS:
                    bits = op[1]
                    ok = bool(bits >> c & 1 or (nocase and bits >> Bytes.SWAP[c] & 1)) != op[2]
                elif code == Op.NOT_BYTE:
                    ok = c != op[1]
                elif code == Op.MASK:
                    ok = c & op[1] == op[2]
                elif code == Op.NOT_MASK:
                    ok = c & op[1] != op[2]
                elif code in (Op.WORD, Op.NON_WORD):
                    ok = (Bytes.WORD >> c & 1 == 1) == (code == Op.WORD)
                elif code in (Op.SPACE, Op.NON_SPACE):
                    ok = (Bytes.SPACE >> c & 1 == 1) == (code == Op.SPACE)
                else:
                    ok = (48 <= c <= 57) == (code == Op.DIGIT)
                if not ok:
                    self.live -= 1
                    del threads[i]
                    continue
                if code != Op.SKIP:
                    t[0] += 1
                moved = self._settle(t)
                threads[i : i + 1] = moved
                i += len(moved)
                continue
            if code in Op.TESTS:
                key = (t[0], t[1], t[2])
                if key in tested:
                    # back at a test it has passed this step, counts unchanged: what follows would
                    # repeat what followed the first time, without end
                    self.live -= 1
                    del threads[i]
                    continue
                tested.add(key)
                if code == Op.START:
                    ok = start_ok
                elif code == Op.END:
                    ok = end_ok
                else:
                    ok = (before != here) == (code == Op.EDGE)
                if not ok:
                    self.live -= 1
                    del threads[i]
                    continue
                t[0] += 1
                threads[i : i + 1] = self._settle(t)
                continue
            # DONE
            hits += 1
            if self.every:
                self.live -= 1
                del threads[i]
                continue
            self.live -= len(threads) - i
            del threads[i:]
            break
        return threads, hits

    @staticmethod
    def _word(data: bytes, p: int, width: int) -> bool:
        if p < 0 or p + width > len(data):
            return False
        c = data[p]
        return bool(Bytes.WORD >> c & 1) and (width == 1 or data[p + 1] == 0)


class Lanes:
    """Runs the layout of a hex pattern without alternatives: one instruction at a time over
    the set of positions still matching, a skip adding every position it can reach. Forwards it
    ends at the first position that reaches the end (the shortest match); `every` hears each."""

    def __init__(self, ops: list[tuple[int, ...]]) -> None:
        self.ops = ops

    def run(self, entry: int, data: bytes, at: int, *, backwards: bool = False,
            every: Callable[[int, int], None] | None = None) -> int:  # fmt: skip
        ops = self.ops
        step = -1 if backwards else 1
        reach = min(at if backwards else len(data) - at, REACH)
        pc = entry
        lanes = [[at - 1 if backwards else at, 0]]
        rnd = 0
        while lanes:
            op = ops[pc]
            code = op[0]
            k = 0
            while k < len(lanes):
                lane = lanes[k]
                if lane[1] != rnd:
                    k += 1
                    continue
                done = at - lane[0] - 1 if backwards else lane[0] - at
                ok = False
                if code == Op.DONE:
                    if every is None:
                        return done
                    every(max(lane[0] + 1, 0) if backwards else at, min(done, reach))
                elif code == Op.SKIP:
                    lo, hi = op[1], op[2]
                    if done + lo < reach:
                        ok = True
                        place = k
                        nxt_op = ops[pc + 1]
                        for j in range(lo + 1, hi + 1):
                            if done + j >= reach:
                                break
                            spot = lane[0] + j * step
                            while place + 1 < len(lanes) and lanes[place + 1][0] <= spot:
                                place += 1
                            if lanes[place][1] == rnd + 1 and lanes[place][0] == spot:
                                continue
                            if nxt_op[0] == Op.BYTE and nxt_op[1] != data[spot]:
                                continue
                            lanes.insert(place + 1, [spot, rnd + 1])
                        lane[0] += lo * step
                elif done < reach:
                    c = data[lane[0]]
                    if code == Op.ANY:
                        ok = True
                    elif code == Op.BYTE:
                        ok = c == op[1]
                    elif code == Op.NOT_BYTE:
                        ok = c != op[1]
                    elif code == Op.MASK:
                        ok = c & op[1] == op[2]
                    else:
                        ok = c & op[1] != op[2]
                    if ok:
                        lane[0] += step
                if ok:
                    lane[1] = rnd + 1
                    k += 1
                else:
                    del lanes[k]
            if code != Op.DONE:
                pc += 1
            rnd += 1
        return -1


# -- anchors ------------------------------------------------------------------


class Anchor:
    """A run of at most `ANCHOR` bytes a string's matches must contain, `back` bytes into the
    string; `term` is the pattern term it begins at (None for a plain text string)."""

    __slots__ = ("back", "data", "masks", "term")

    def __init__(self, data: list[int], masks: list[int], back: int, term: Term | None) -> None:
        self.data, self.masks, self.back, self.term = data, masks, back, term

    def copy(self) -> Anchor:
        return Anchor(list(self.data), list(self.masks), self.back, self.term)


class Anchors:
    """Which anchors a pattern's search looks for. Each candidate run is scored for how rarely
    it should occur in data (`score`): longer, with fewer wildcards and fewer common bytes, more
    varied. Alternatives need an anchor in every branch; the best-scoring choice wins."""

    COMMON: ClassVar[frozenset[int]] = frozenset((0x00, 0x20, 0xCC, 0xFF))
    FILLER: ClassVar[frozenset[int]] = frozenset((0x00, 0x20, 0x90, 0xCC, 0xFF))

    @staticmethod
    def score(data: list[int], masks: list[int]) -> int:
        points = 0
        distinct: set[int] = set()
        for b, m in zip(data, masks, strict=True):
            if m == 0:
                points -= 10
            elif m in (0x0F, 0xF0):
                points += 4
            elif m == 0xFF:
                if b in Anchors.COMMON:
                    points += 12
                elif 0x61 <= Bytes.LOWER[b] <= 0x7A:
                    points += 18
                else:
                    points += 20
                distinct.add(b)
        if len(distinct) == 1 and distinct <= Anchors.FILLER:
            points -= 10 * len(data)
        else:
            points += 2 * len(distinct)
        return TOP_SCORE - 22 * ANCHOR + points

    @staticmethod
    def trim(data: list[int], masks: list[int]) -> tuple[list[int], list[int], int]:
        """Wildcards cut from both ends; a run with as many wildcards as known bytes kept to its
        first byte. Returns the run and how many bytes were cut from its front."""
        left = 0
        while left < len(masks) and masks[left] == 0:
            left += 1
        right = len(masks)
        while right > left and masks[right - 1] == 0:
            right -= 1
        if right == left:
            return [], [], 0
        known = sum(1 for m in masks[left:right] if m == 0xFF)
        unknown = sum(1 for m in masks[left:right] if m == 0)
        if unknown >= known:
            right = left + 1
        return data[left:right], masks[left:right], left

    def __init__(self) -> None:
        # the group leaves are being added to: ["any", members]; members are leaves
        # ["run", data, masks, terms] and ["all", group, group] for alternatives
        self.group: list[Any] = ["any", []]
        self.run: list[Term] = []
        self.best: tuple[list[int], list[int], list[Term]] = ([], [], [])
        self.best_score = -1

    @staticmethod
    def of(root: Term) -> tuple[list[Anchor], int]:
        """The anchors chosen for a pattern tree, wildcards expanded, and the worst score."""
        a = Anchors()
        top = a.group
        a._to(top)
        a._walk(root)
        a._to(top)
        chosen, worst = Anchors._choose(top)
        return Anchors._expand(chosen), worst

    def _to(self, group: list[Any]) -> None:
        """Closes the run being collected into the current group, then collects into `group`."""
        if self.run:
            data = [t.value & 0xFF for t in self.run]
            masks = [t.mask & 0xFF for t in self.run]
            cut_data, cut_masks, cut = Anchors.trim(data, masks)
            if Anchors.score(cut_data, cut_masks) > self.best_score:
                leaf = ["run", cut_data, cut_masks, self.run[cut:]]
            else:
                leaf = ["run", *self.best]
            self.group[1].append(leaf)
            self.run = []
        self.group = group
        self.best_score = -1

    def _take(self, t: Term) -> None:
        if len(self.run) < ANCHOR:
            self.run.append(t)
            self.best = ([x.value & 0xFF for x in self.run], [x.mask & 0xFF for x in self.run],
                         list(self.run))  # fmt: skip
        elif self.best_score < TOP_SCORE:
            data = [x.value & 0xFF for x in self.run]
            masks = [x.mask & 0xFF for x in self.run]
            cut_data, cut_masks, cut = Anchors.trim(data, masks)
            s = Anchors.score(cut_data, cut_masks)
            if s > self.best_score:
                self.best = (cut_data, cut_masks, self.run[cut : cut + len(cut_data)])
                self.best_score = s
            self.run = [*self.run[1:], t]

    def _walk(self, t: Term) -> None:
        k = t.kind
        if k in (LIT, MASKED, ANY):
            self._take(t)
        elif k == SEQ:
            for kid in t.kids:
                self._walk(kid)
        elif k == EITHER:
            here = self.group
            left: list[Any] = ["any", []]
            right: list[Any] = ["any", []]
            here[1].append(["all", left, right])
            self._to(left)
            self._walk(t.kids[0])
            self._to(right)
            self._walk(t.kids[1])
            self._to(here)
        elif k == PLUS:
            self._walk(t.kids[0])
            self._to(self.group)
        elif k == COUNT:
            for _ in range(min(t.lo, ANCHOR)):
                self._walk(t.kids[0])
            self._to(self.group)
        else:
            self._to(self.group)

    @staticmethod
    def _choose(node: list[Any]) -> tuple[list[Anchor], int]:
        if node[0] == "run":
            data, masks, cut = Anchors.trim(node[1], node[2])
            if not data:
                return [], 0
            return [Anchor(data, masks, 0, node[3][cut])], Anchors.score(data, masks)
        if node[0] == "any":
            best: list[Anchor] = []
            top = 0
            for member in node[1]:
                chosen, s = Anchors._choose(member)
                if s > top:
                    best, top = chosen, s
                if top == TOP_SCORE:
                    break
            return best, top
        out: list[Anchor] = []
        worst = TOP_SCORE
        for member in node[1:]:
            chosen, s = Anchors._choose(member)
            worst = min(worst, s)
            out = chosen + out
        return out, worst

    @staticmethod
    def _expand(anchors: list[Anchor]) -> list[Anchor]:
        """Every wildcard byte replaced by each value it allows, in place in the list."""
        k = 0
        while k < len(anchors):
            a = anchors[k]
            widened = False
            for i, m in enumerate(a.masks):
                if m == 0xFF:
                    continue
                if m == 0:
                    lo, hi, step = 0, 255, 1
                elif m == 0x0F:
                    lo, hi, step = a.data[i], a.data[i] | 0xF0, 0x10
                elif m == 0xF0:
                    lo, hi, step = a.data[i], a.data[i] | 0x0F, 1
                else:
                    continue
                widened = True
                a.data[i], a.masks[i] = lo, 0xFF
                more = []
                for v in range(lo + step, hi + 1, step):
                    b = a.copy()
                    b.data[i] = v
                    more.append(b)
                anchors[k + 1 : k + 1] = more
            if not widened:
                k += 1
        return anchors

    @staticmethod
    def of_text(text: bytes) -> tuple[Anchor, int]:
        """A text string's anchor: its best-scoring `ANCHOR`-byte window."""
        first = list(text[:ANCHOR])
        best = Anchor(first, [0xFF] * len(first), 0, None)
        top = Anchors.score(best.data, best.masks)
        i = ANCHOR
        while i < len(text) and top < TOP_SCORE:
            window = list(text[i - ANCHOR + 1 : i + 1])
            s = Anchors.score(window, [0xFF] * ANCHOR)
            if s > top:
                best, top = Anchor(window, [0xFF] * ANCHOR, i - ANCHOR + 1, None), s
            i += 1
        return best, top

    @staticmethod
    def wide(anchors: list[Anchor]) -> list[Anchor]:
        out: list[Anchor] = []
        for a in anchors:
            data = [x for b in a.data for x in (b, 0)][:ANCHOR]
            out.insert(0, Anchor(data, [0xFF] * len(data), a.back * 2, a.term))
        return out

    @staticmethod
    def cases(anchors: list[Anchor]) -> list[Anchor]:
        """Every other-case spelling of each anchor's letters (the anchor itself not included)."""
        out: list[Anchor] = []
        for a in anchors:
            made: list[list[int]] = []
            Anchors._respell(a.data, 0, made)
            for data in made:
                out.insert(0, Anchor(data, [0xFF] * len(data), a.back, a.term))
        return out

    @staticmethod
    def _respell(data: list[int], at: int, made: list[list[int]]) -> None:
        if at + 1 < len(data):
            Anchors._respell(data, at + 1, made)
        c = data[at] if at < len(data) else -1
        if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
            other = list(data)
            other[at] = c ^ 0x20
            made.append(other)
            if at + 1 < len(data):
                Anchors._respell(other, at + 1, made)

    @staticmethod
    def xored(anchors: list[Anchor], lo: int, hi: int) -> list[Anchor]:
        out: list[Anchor] = []
        for a in anchors:
            for key in range(lo, hi + 1):
                data = [b ^ key for b in a.data][:ANCHOR]
                out.insert(0, Anchor(data, [0xFF] * len(data), a.back, a.term))
        return out
