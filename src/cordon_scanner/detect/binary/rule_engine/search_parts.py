"""What a string search is built from: a string cut into the parts it is searched by (literal runs,
masked runs, chains, gaps) with the anchor and event shapes the search records, and the matcher a
condition's `matches` runs.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.chain import Chain
from cordon_scanner.detect.binary.rule_engine.pattern import (
    ANY,
    CLASS,
    COUNT,
    DIGIT,
    GAP,
    LIT,
    MASKED,
    NON_DIGIT,
    NON_SPACE,
    NON_WORD,
    NOT,
    NOT_MASKED,
    SEQ,
    SPACE,
    WORD,
    Program,
    Term,
)
from cordon_scanner.detect.binary.rule_engine.pattern_readers import (
    RegexReader,
)
from cordon_scanner.detect.binary.rule_engine.threads import Threads

#: An anchor as searched for: its bytes, how far into the string it starts, and where the forward
#: and backward layouts start from it (None for text).
AnchorAt = tuple[bytes, int, int | None, int | None]

#: An anchor occurrence, ordered as it is checked: (end, -length, -order, part, anchor, offset).
Event = tuple[int, int, int, int, AnchorAt, int]


class Part:
    """One piece of a string: plain bytes (`text`) or a pattern (`forward`/`backward` layouts),
    and the anchors that find it. `gap` is the (least, most) distance from the previous part."""

    #: The terms that read one byte: a run of one of them repeated is a factor (`factor_of`).
    SINGLE: ClassVar[frozenset[int]] = frozenset(
        {
            LIT,
            MASKED,
            ANY,
            NOT,
            NOT_MASKED,
            CLASS,
            WORD,
            NON_WORD,
            SPACE,
            NON_SPACE,
            DIGIT,
            NON_DIGIT,
        }
    )
    #: The shortest run worth a factor test.
    FACTOR_MIN: ClassVar[int] = 8

    #: The shortest literal run worth looking for before the anchors (`literals_in`).
    LITERAL_MIN: ClassVar[int] = 3

    @staticmethod
    def literals_in(root: Term) -> list[bytes]:
        """Runs of consecutive literal bytes on the terms every match goes through (the root and
        the sequences under it, never inside an alternative or a repeat), `LITERAL_MIN` long or
        longer, longest first. A piece of data without one of them holds no match."""
        flat: list[Term] = []
        todo = [root]
        while todo:
            term = todo.pop()
            if term.kind == SEQ:
                todo.extend(reversed(term.kids))
            else:
                flat.append(term)
        runs: list[bytes] = []
        run = bytearray()
        for term in [*flat, Term(ANY)]:
            if term.kind == LIT:
                run.append(term.value)
                continue
            if len(run) >= Part.LITERAL_MIN:
                runs.append(bytes(run))
            run = bytearray()
        return sorted(set(runs), key=lambda r: -len(r))

    @staticmethod
    def heavy_in(root: Term) -> bool:
        """Whether a counted repeat or jump in `root` may run `Chain.HEAVY` times or more."""
        todo = [root]
        while todo:
            term = todo.pop()
            if term.kind in (COUNT, GAP) and term.hi >= Chain.HEAVY:
                return True
            todo.extend(term.kids)
        return False

    #: The most runs `factors_of` keeps.
    FACTORS: ClassVar[int] = 4

    @staticmethod
    def factors_of(root: Term) -> list[tuple[int, int]]:
        """Runs every match must hold: a term that reads one byte, repeated at least `lo` times
        in a row, among the terms every match goes through (the root and the sequences under it,
        never inside an alternative or an optional repeat). Each is (its forward entry, `lo`);
        the longest `FACTORS` of those of `FACTOR_MIN` or more, longest first. Each one alone
        rules out the places it does not occur, so a run the data has everywhere costs a test and
        a rarer one does the work."""
        found: list[tuple[int, int]] = []
        todo = [root]
        while todo:
            term = todo.pop()
            if term.kind == SEQ:
                todo.extend(term.kids)
                continue
            if term.kind != COUNT or term.lo < Part.FACTOR_MIN or term.fwd is None:
                continue
            if len(term.kids) == 1 and term.kids[0].kind in Part.SINGLE:
                found.append((term.fwd, term.lo))
        found.sort(key=lambda f: -f[1])
        return found[: Part.FACTORS]

    #: Forward runs from one entry before its gate (`can_start`) is worked out.
    GATE_AFTER: ClassVar[int] = 256

    def __init__(self) -> None:
        self.text: bytes | None = None
        self.forward: list[tuple[int, ...]] = []
        self.backward: list[tuple[int, ...]] = []
        self.root_entry: int | None = None
        #: Runs every match of the part holds: (the forward entry of the term read, at least how
        #: many of it in a row), longest first (`Part.factors_of`).
        self.factors: list[tuple[int, int]] = []
        #: The part as a chain of class repeats, when it is one (`rule_engine.chain.Chain`).
        self.chain: Chain | None = None
        #: Runs of literal bytes every match of the part holds (`Part.literals_in`).
        self.required: list[bytes] = []
        #: The part holds a repeat long enough for runs to keep many threads (`Part.heavy_in`):
        #: only then is gating its anchors on the bytes around them worth its cost.
        self.heavy = False
        self.anchors: list[AnchorAt] = []
        self.fits = False  # text short enough that an anchor occurrence is the match
        #: Steps the layouts have taken, kept across runs and files (`rule_engine.pattern.Memo`).
        self.memo: dict[tuple[bool, ...], Any] = {}
        self._runners: tuple[Threads, Threads] | None = None
        self._gates: dict[int, Any] = {}  # entry -> its forward gate (None: none helps)
        self._runs: dict[int, int] = {}  # entry -> forward runs before its gate is built
        self.gap = (0, 0)

    def can_start(self, entry: int, data: bytes, at: int, nocase: bool, dotall: bool) -> bool:
        """Whether a one-byte-wide forward run from `entry` at `at` can do anything: a check in C
        (`Threads.prefilter`) that turns away the occurrences whose run would die at once."""
        gate = self._gates.get(entry, False)
        if gate is False:
            # built once an entry has run often enough to repay working it out
            runs = self._runs[entry] = self._runs.get(entry, 0) + 1
            if runs < Part.GATE_AFTER:
                return True
            gate = self.gate(entry, nocase, dotall)
        return gate is None or gate.match(data, at) is not None

    def gate(self, entry: int, nocase: bool, dotall: bool) -> re.Pattern[bytes] | None:
        """The forward gate of `entry` (`can_start`), built once: zero-width at every position a
        one-byte-wide run from there can do anything at; None when none helps."""
        gate: re.Pattern[bytes] | bool | None = self._gates.get(entry, False)
        if gate is False:
            gate = self._gates[entry] = self.runners()[0].prefilter(
                entry, nocase=nocase, dotall=dotall, depth=2, chain=8
            )
        assert not isinstance(gate, bool)  # noqa: S101 - False only before it is built
        return gate

    def runners(self) -> tuple[Threads, Threads]:
        """The forward and backward runners of this part, made once and kept."""
        if self._runners is None:
            self._runners = (Threads(self.forward, self.memo), Threads(self.backward, self.memo))
        return self._runners


class Matcher:
    """A condition's `matches`: whether a regular expression matches anywhere in a text."""

    def __init__(self, source: bytes, marks: str) -> None:
        reader = RegexReader(source)
        root = reader.read()
        program = Program(root, backwards=False)
        self.ops, self.entry = program.ops, program.entry
        self.nocase, self.dotall = "i" in marks, "s" in marks
        self.memo: dict[tuple[bool, ...], Any] = {}

    def run(self, text: bytes) -> int:
        """Where the match the run settles on ends, counted from the text's start; -1 for none."""
        return Threads(self.ops, self.memo).run(
            0, text, 0, nocase=self.nocase, dotall=self.dotall, scan=True
        )

    def test(self, text: bytes) -> bool:
        return self.run(text) >= 0


__all__ = ["AnchorAt", "Event", "Matcher", "Part"]
