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
from typing import Any, ClassVar

#: The longest a jump in a layout may be, in layout bytes, either way.
MAX_JUMP = 32767

#: The most forks one layout may contain.
MAX_FORKS = 128


class PatternError(ValueError):
    """A pattern that does not read, or cannot be laid out."""


class RunError(RuntimeError):
    """A run that went past one of its fixed bounds."""


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


class Memo:
    """The steps one layout has taken in one run mode: thread lists numbered as they are first
    seen, and for each (list, byte, surroundings) the list it led to and the matches it reached.
    Past `Memo.LIMIT` steps, or once its lists weigh `Memo.WEIGHT` pointers (`weight`), it starts
    afresh: its size is bounded whatever the pattern and the data (a list can hold up to
    `MAX_THREADS` threads, so a count of lists alone does not bound it). `WEIGHT` is about 64 MB.
    """

    LIMIT: ClassVar[int] = 1 << 16
    WEIGHT: ClassVar[int] = 1 << 23

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
        #: For an entry point, the single path its runs start along (`Threads.path`).
        self.paths: dict[tuple[int, int, int], list[bytes]] = {}
        #: For an entry point, a pattern finding where a run from it can do anything (`prefilter`).
        self.filters: dict[tuple[int, int, int], re.Pattern[bytes] | None] = {}
        #: Every thread the lists in `states` hold, each kept once.
        self.threads: dict[tuple[Any, ...], tuple[Any, ...]] = {}
        #: The size of `states`, in pointers: one per thread a list holds, a dozen per thread kept.
        self.weight = 0

    def full(self) -> bool:
        return len(self.states) > Memo.LIMIT or self.weight > Memo.WEIGHT

    def state(self, keys: tuple[tuple[Any, ...], ...]) -> int:
        number = self.numbers.get(keys)
        if number is None:
            # each thread is kept once, shared by every list holding it: a list costs a pointer
            # a thread, and a thread first seen costs about a dozen more (`WEIGHT` counts both)
            shared, before = self.threads, len(self.threads)
            keys = tuple([shared.setdefault(k, k) for k in keys])
            number = self.numbers[keys] = len(self.states)
            self.states.append(keys)
            self.weight += len(keys) + 1 + 12 * (len(shared) - before)
        return number

    def remember(self, key: tuple[Any, ...], went: tuple[int, int]) -> None:
        if len(self.steps) >= Memo.LIMIT:
            self.steps.clear()
        self.steps[key] = went


__all__ = [
    "ANY",
    "CLASS",
    "COUNT",
    "DIGIT",
    "EDGE",
    "EITHER",
    "EMPTY",
    "END",
    "GAP",
    "LIT",
    "MASKED",
    "MAX_FORKS",
    "MAX_JUMP",
    "NON_DIGIT",
    "NON_EDGE",
    "NON_SPACE",
    "NON_WORD",
    "NOT",
    "NOT_MASKED",
    "PLUS",
    "SEQ",
    "SPACE",
    "STAR",
    "START",
    "TERM_OPS",
    "WORD",
    "Bytes",
    "Memo",
    "Op",
    "PatternError",
    "Program",
    "RunError",
    "Term",
]
