"""cordon-rule's chain matcher: every match of a pattern that is a chain of byte-class repeats,
worked out from the lengths of class runs instead of thread by thread.

A chain is a sequence of terms each reading one byte from a class, repeated from `lo` to `hi`
times, greedily -- ` +\\s{475}\\s{402,}`, `[^a]{167,}[0-9]*.{513}[0-9]{1,6}` -- whose first term
reads at least once. Running such a pattern thread by thread costs a thread for every way the
bytes read so far could split between the terms, which over long runs of one class is hundreds
of threads a step; the chain matcher costs a few lookups a match:

- For each term `i`, `feasible[i]` is the set of positions from which terms `i..` can match (any
  lengths), as sorted disjoint intervals, worked out from the last term back over the runs of each
  term's class.
- From each position where the whole chain can match, the match is built term by term: each
  takes the most bytes it can (it is greedy) that still leave the rest a feasible position. That
  is the match a run tries first, so the one it reports.

Matches are found as a search finds them, from anchor occurrences: the chain matcher takes the
anchors' offsets and gives, for each start, what running the anchors would. An anchor at `q` in
the chain's first term starts a match there and reads on greedily; when that term is a `+`, its
backward run may also read more of the term's bytes before `q`, so every start back to the start
of the term's run (within `REACH`) is a match too, and a start reached from several anchors keeps
the last one's, as the search records it. A run reads at most `rule_pattern.REACH` bytes, so a
match that long is left to the runs: `matches` gives no answer then, and none for an anchor
outside the first term.
"""

from __future__ import annotations

import bisect
import re
import time
from typing import ClassVar

from cordon_scanner.detect.binary.rule_pattern import (
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
    PLUS,
    REACH,
    SEQ,
    SPACE,
    STAR,
    WORD,
    Program,
    Term,
    Threads,
)

#: Positions, as sorted disjoint closed intervals.
Spans = list[tuple[int, int]]


class Chain:
    """A pattern as a chain of class repeats: for each term, the one-byte term it repeats and
    its least and most count."""

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
    RUNS: ClassVar[re.Pattern[bytes]] = re.compile(b"\x01+")

    def __init__(self, terms: list[tuple[Term, int, int]]) -> None:
        self.terms = terms
        #: The first term is a `+`: a backward run from an anchor in it reads more of it.
        self.first_repeats = False
        #: Each term's bytes, as a translate table, by (nocase, dotall).
        self._tables: dict[tuple[bool, bool], list[bytes]] = {}

    @staticmethod
    def of(root: Term) -> Chain | None:
        """The chain `root` is, or None when it is not one."""
        flat: list[Term] = []
        todo = [root]
        while todo:
            term = todo.pop()
            if term.kind == SEQ:
                todo.extend(reversed(term.kids))
            else:
                flat.append(term)
        terms: list[tuple[Term, int, int]] = []
        for term in flat:
            if term.kind in Chain.SINGLE:
                terms.append((term, 1, 1))
            elif term.kind == GAP:
                if not term.eager:
                    return None
                terms.append((Term(ANY), term.lo, term.hi))
            elif term.kind in (COUNT, PLUS, STAR):
                if not term.eager or len(term.kids) != 1 or term.kids[0].kind not in Chain.SINGLE:
                    return None
                lo, hi = (
                    (term.lo, term.hi)
                    if term.kind == COUNT
                    else (1 if term.kind == PLUS else 0, REACH * 4)
                )
                terms.append((term.kids[0], lo, hi))
            else:
                return None
        if not terms or terms[0][1] < 1:
            return None
        chain = Chain(terms)
        chain.first_repeats = flat[0].kind == PLUS
        return chain

    def tables(self, nocase: bool, dotall: bool) -> list[bytes]:
        """Each term's bytes, read as the matcher reads them: a run of a layout of the term
        alone, so case folding and `.` are exactly the matcher's."""
        key = (nocase, dotall)
        if key not in self._tables:
            out = []
            for term, _, _ in self.terms:
                alone = Term(term.kind, value=term.value, mask=term.mask)
                alone.bits, alone.negated = term.bits, term.negated
                program = Program(alone, backwards=False)
                reads = Threads(program.ops).first_reads(
                    alone.fwd or 0, nocase=nocase, dotall=dotall
                )
                accepted = reads or frozenset()
                out.append(bytes(1 if b in accepted else 0 for b in range(256)))
            self._tables[key] = out
        return self._tables[key]

    def matches(
        self,
        data: bytes,
        anchors: list[int],
        *,
        backward: bool,
        nocase: bool,
        dotall: bool,
        deadline: float | None = None,
    ) -> list[tuple[int, int]] | None:
        """(start, length) of every match the anchor occurrences at `anchors` (offsets where the
        first term would start; sorted) give, by start. With `backward`, a match may also start
        earlier, back over the first term's bytes. None when a match reads too far to be told
        here."""
        n = len(data)
        runs = [
            [(m.start(), m.end()) for m in Chain.RUNS.finditer(data.translate(table))]
            for table in self.tables(nocase, dotall)
        ]
        feasible: list[Spans] = [[] for _ in self.terms] + [[(0, n)]]
        for i in range(len(self.terms) - 1, -1, -1):
            _, lo, hi = self.terms[i]
            feasible[i] = Chain._before(runs[i], feasible[i + 1], lo, hi)
        Chain._in_time(deadline)
        lengths: list[tuple[int, int]] = []  # (anchor, length read on from it)
        for count, q in enumerate(anchors):
            if count % 4096 == 0:
                Chain._in_time(deadline)
            if not Chain.within(feasible[0], q):
                continue
            length = self._greedy(runs, feasible, q)
            if length >= REACH - 1:
                return None  # the run's reach would cut it
            lengths.append((q, length))
        if not (backward and self.first_repeats):
            return lengths
        # each start keeps the last anchor whose backward run reaches it: every start from the
        # start of the first term's run (no more than `REACH` back) up to the anchor
        out: list[tuple[int, int]] = []
        floor = n + 1
        first = runs[0]
        for q, length in reversed(lengths):
            begin = max(q - REACH, Chain._run_start(first, q))
            top = min(q, floor - 1)
            for s in range(top, begin - 1, -1):
                out.append((s, q - s + length))
            floor = min(floor, begin)
        out.reverse()
        return out

    def _greedy(self, runs: list[list[tuple[int, int]]], feasible: list[Spans], start: int) -> int:
        """How far the chain reads from `start`: each term takes the most bytes it can that
        leave the rest a feasible position."""
        p = start
        for i, (_, lo, hi) in enumerate(self.terms):
            end = Chain._run_end(runs[i], p)
            p = Chain._last_in(feasible[i + 1], p + lo, min(p + hi, end))
        return p - start

    @staticmethod
    def _in_time(deadline: float | None) -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("matching took longer than the time allowed")

    @staticmethod
    def _run_start(runs: list[tuple[int, int]], p: int) -> int:
        """Where the run of the term's class holding `p` starts; `p` when none holds it."""
        i = bisect.bisect_right(runs, (p, 1 << 62)) - 1
        if i >= 0 and runs[i][0] <= p < runs[i][1]:
            return runs[i][0]
        return p

    @staticmethod
    def within(spans: Spans, p: int) -> bool:
        i = bisect.bisect_right(spans, (p, 1 << 62)) - 1
        return i >= 0 and spans[i][0] <= p <= spans[i][1]

    @staticmethod
    def _run_end(runs: list[tuple[int, int]], p: int) -> int:
        """Where the run of the term's class holding `p` ends; `p` when none holds it."""
        i = bisect.bisect_right(runs, (p, 1 << 62)) - 1
        if i >= 0 and runs[i][0] <= p < runs[i][1]:
            return runs[i][1]
        return p

    @staticmethod
    def _last_in(spans: Spans, lo: int, hi: int) -> int:
        """The largest position of `spans` in [lo, hi]; the chain guarantees one."""
        i = bisect.bisect_right(spans, (hi, 1 << 62)) - 1
        a, b = spans[i]
        best = min(b, hi)
        assert best >= lo and best >= a  # noqa: S101 - feasibility was worked out for this
        return best

    @staticmethod
    def _before(runs: list[tuple[int, int]], after: Spans, lo: int, hi: int) -> Spans:
        """Positions from which `lo..hi` bytes of the class (its `runs`), then a position of
        `after`, can be read."""
        found: Spans = list(after) if lo == 0 else []
        starts = [s for s, _ in after]
        least = max(lo, 1)  # with lo 0 the empty choice is `after` itself
        for a, e in runs:
            # p in [a, e - least] reads x in [least, min(hi, e - p)] bytes, landing in
            # [p + least, min(p + hi, e)]; that window must meet some interval [u, v] of `after`
            if e - a < least:
                continue
            k = max(0, bisect.bisect_right(starts, a + least) - 1)
            while k < len(after) and after[k][0] <= e:
                u, v = after[k]
                p_lo, p_hi = max(a, u - hi), min(e - least, v - least)
                if p_lo <= p_hi:
                    found.append((p_lo, p_hi))
                k += 1
        return Chain._merge(found)

    @staticmethod
    def _merge(spans: Spans) -> Spans:
        out: Spans = []
        for a, b in sorted(spans):
            if out and a <= out[-1][1] + 1:
                if b > out[-1][1]:
                    out[-1] = (out[-1][0], b)
            else:
                out.append((a, b))
        return out


__all__ = ["Chain", "Spans"]
