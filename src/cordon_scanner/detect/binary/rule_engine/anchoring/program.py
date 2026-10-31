"""A pattern part's program for the native runner (`_anchors.threads_run`, `pattern_hits`), in the
format the modelling team set (spec v2), and the whole-string find over it (`PatternFind`).

A program is int64s: a header of seven (magic, version, op count, class count, forward entry,
backward entry, the deepest the counted loops nest), then each op as six (code and its
operands), then each class as four (256 bits, bit c in word c >> 6). `Encoded.of` works it out
from a part's layout once; the nesting is read from the layout's control flow, so it is the
real depth a thread's counts can reach, which the runner checks as it runs.
"""

from __future__ import annotations

import time
from array import array
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine import threads
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
from cordon_scanner.detect.binary.rule_engine.hits import Hits
from cordon_scanner.detect.binary.rule_engine.pattern import Op, RunError


class Encoded:
    MAGIC: ClassVar[int] = 0x43505247
    VERSION: ClassVar[int] = 2
    #: The deepest nesting the runner takes; a deeper program is found by the hunt.
    DEEPEST: ClassVar[int] = 64

    @staticmethod
    def depth(ops: list[tuple[int, ...]]) -> int:
        """The deepest the counts stack goes along any path of `ops`: each instruction walked at
        each depth it is reached at, from every one at depth 0 (a run starts from an entry outside
        every counted loop, so this is the real depth, never less). ENTER opens a count for its
        body; AGAIN loops at the same depth or leaves one lower."""
        seen: set[tuple[int, int]] = set()
        todo = [(pc, 0) for pc in range(len(ops))]
        deepest = 0
        while todo:
            pc, d = todo.pop()
            if (pc, d) in seen or not 0 <= pc < len(ops):
                continue
            seen.add((pc, d))
            deepest = max(deepest, d)
            op = ops[pc]
            code = op[0]
            if code == Op.DONE:
                continue
            if code == Op.GOTO:
                todo.append((op[1], d))
            elif code == Op.FORK:
                todo += [(op[2], d), (pc + 1, d)]
            elif code == Op.ENTER:
                todo += [(pc + 1, d + 1), (op[3], d)]
            elif code == Op.AGAIN:
                todo += [(op[3], d), (pc + 1, max(d - 1, 0))]
            else:
                todo.append((pc + 1, d))
        return deepest

    @staticmethod
    def of(ops: list[tuple[int, ...]]) -> bytes | None:
        """`ops` as a program, or None when the runner does not take it (nested too deep)."""
        depth = Encoded.depth(ops)
        if depth > Encoded.DEEPEST:
            return None
        classes: list[int] = []
        flat = array("q")
        for op in ops:
            if op[0] == Op.CLASS:
                classes.append(op[1])
                record: tuple[int, ...] = (Op.CLASS, len(classes) - 1, int(op[2]))
            else:
                record = tuple(int(x) for x in op)
            flat.extend((*record, 0, 0, 0, 0, 0, 0)[:6])
        head = array("q", (Encoded.MAGIC, Encoded.VERSION, len(ops), len(classes), 0, 0, depth))
        for bits in classes:
            for k in range(4):
                word = (bits >> (64 * k)) & ((1 << 64) - 1)
                flat.append(word - (1 << 64) if word >> 63 else word)
        return head.tobytes() + flat.tobytes()


class PatternFind:
    """A regular expression's or a hex string with alternatives' whole find in one native call
    (`_anchors.pattern_hits`): its anchors' occurrences in, its matches out, as `scan._Hunt`
    finds them with `threads.Threads`. Only for a string of one pattern part, not `plain` (that
    is `HexFind`'s), with no chain, base64 or anchorless part; every other string, and every
    string where the extension is not in use, is found by the hunt itself, its twin."""

    ASCII, WIDE, NOCASE, DOTALL, FULLWORD, GREEDY = 1, 2, 4, 8, 16, 32

    @staticmethod
    def programs(search: Any) -> tuple[bytes, bytes] | None:
        """The part's forward and backward programs, worked out once; None when not found so."""
        if search.programs is None:
            search.programs = PatternFind._encoded(search) or False
        return search.programs or None

    @staticmethod
    def _encoded(search: Any) -> tuple[bytes, bytes] | None:
        f = search.flags
        if not Automaton.NATIVE or len(search.parts) != 1 or search.zeros:
            return None
        part = search.parts[0]
        if (
            part.text is not None
            or f.get("plain")
            or part.chain
            or "base64" in f
            or "base64wide" in f
        ):
            return None
        forward, backward = Encoded.of(part.forward), Encoded.of(part.backward)
        if forward is None or backward is None:
            return None
        return forward, backward

    @staticmethod
    def hits(
        search: Any, data: bytes, seen: dict[Any, Any], fixed: int | None, max_hits: int,
        deadline: float | None,
    ) -> Hits:  # fmt: skip
        forward, backward = search.programs
        f = search.flags
        owners: list[tuple[list[int], int, int, int, int, int]] = []

        def own(starts: list[int], length: int, holders: list[tuple[int, int, Any]]) -> None:
            owners.extend(
                (starts, length, length + a[1], order, -1 if a[2] is None else a[2],
                 -1 if a[3] is None else a[3])
                for order, _, a in holders
            )  # fmt: skip

        for needle, length, holders in search.needles:
            starts = seen.get(needle)
            if starts is None:
                starts = seen[needle] = search.located(data, needle, seen)
            own(starts, length, holders)
        for folded, length, spellings in search.folds:
            starts = seen.get(("folded", folded))
            if starts is None:
                lowered = seen.get(("lowered",))
                if lowered is None:
                    lowered = seen[("lowered",)] = data.lower()
                starts = seen[("folded", folded)] = search.located(lowered, folded, seen, True)
            spelled: dict[bytes, list[int]] = {}
            for at in starts:
                spelled.setdefault(data[at : at + length], []).append(at)
            for spelling, found in spelled.items():
                own(found, length, spellings[spelling])
        flags = (
            (PatternFind.ASCII if "ascii" in f else 0) | (PatternFind.WIDE if "wide" in f else 0)
            | (PatternFind.NOCASE if "nocase" in f else 0)
            | (PatternFind.DOTALL if "dotall" in f else 0)
            | (PatternFind.FULLWORD if "fullword" in f else 0)
            | (PatternFind.GREEDY if f.get("greedy") else 0)
        )  # fmt: skip
        try:
            starts, lengths = Automaton.MODULE.pattern_hits(
                data, owners, forward, backward, flags, max_hits, -1 if fixed is None else fixed,
                threads.MAX_THREADS, threads.REACH,  # read here, as Threads reads them
                -1.0 if deadline is None else max(deadline - time.monotonic(), 0.0),
            )  # fmt: skip
        except Automaton.MODULE.TooManyThreads as exc:
            raise RunError(str(exc)) from None
        out = Hits()
        out.starts.frombytes(starts)
        out.lengths.frombytes(lengths)
        return out


__all__ = ["Encoded", "PatternFind"]
