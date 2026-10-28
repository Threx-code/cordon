"""Running a pattern: the threads of a laid-out program advanced over the data in step, so a match is
found in one pass without backtracking, and the lanes that run several at once.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.pattern import Bytes, Memo, Op, RunError

#: How far a single run may read from where it starts, in either direction.
REACH = 4096

#: The most threads one run may hold at once.
MAX_THREADS = 1024


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
        self._last: tuple[tuple[bool, ...], Memo] | None = None  # the mode and memo used last

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
        last = self._last
        if last is not None and last[0] == mode and not last[1].full():
            self.flags, self.every = (nocase, dotall), every
            return last[1]
        memo = self.memo.get(mode)
        if memo is None or memo.full():
            memo = self.memo[mode] = Memo()
        self._last = (mode, memo)
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
        self,
        entry: int,
        *,
        nocase: bool = False,
        dotall: bool = False,
        depth: int = 3,
        chain: int = 64,
    ) -> re.Pattern[bytes] | None:
        """A pattern that matches (zero-width) at every position a one-byte-wide forward run from
        `entry` can do anything at: the positions it misses are ones where every thread dies
        within `depth` branching bytes (`chain` along a single path) having matched nothing.
        None when no such pattern helps (the layout tests positions, or the first step already
        decides nothing)."""
        memo = self._memo(False, False, nocase, dotall, False)
        key = (entry, depth, chain)
        if key not in memo.filters:
            body = self._ahead(memo, self._start(memo, entry), depth, chain)
            memo.filters[key] = None if body is None else re.compile(b"(?=" + body + b")")
        return memo.filters[key]

    def path(
        self,
        entry: int,
        *,
        nocase: bool = False,
        dotall: bool = False,
        longest: int = 512,
        backwards: bool = False,
    ) -> list[bytes]:
        """The single path a one-byte-wide run from `entry` starts along (forwards, or with
        `backwards` the bytes read going back): for each of its first steps, the bytes (as a
        translate table: 1 for each, 0 for the rest) that keep a thread alive, as long as only
        one list of threads can follow, none tests a position, no match is reached, and running
        out of data ends the run. Empty when no such path starts there. A position whose bytes
        leave the path is one where the run dies on it."""
        memo = self._memo(backwards, False, nocase, dotall, False)
        key = (entry, -2 if backwards else -1, longest)
        if key in memo.paths:
            return memo.paths[key]
        out: list[bytes] = []
        state = self._start(memo, entry)
        try:
            while len(out) < longest and not self._testing(memo, state):
                if self._step(memo, state, -1, False, Threads.QUIET) != (0, 0):
                    break
                table = bytearray(256)
                follows: set[int] = set()
                for c in range(256):
                    nxt, hits = self._step(memo, state, c, True, Threads.QUIET)
                    if hits:
                        follows = {-1}
                        break
                    if nxt:
                        table[c] = 1
                        follows.add(nxt)
                if len(follows) != 1 or -1 in follows:
                    if -1 not in follows and len(follows) > 1:
                        out.append(bytes(table))  # this step still narrows the starts
                    break
                out.append(bytes(table))
                state = follows.pop()
        except RunError:
            pass
        memo.paths[key] = out
        return out

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
        steps, testing = memo.steps, memo.testing
        steady = 0
        while state:
            if done < reach:
                c = data[pos]
                low = not wide or data[pos + 1] == 0
            else:
                c, low = -1, False
            tested = testing.get(state)
            if tested is None:
                tested = self._testing(memo, state)
            if tested:
                around = (
                    (at <= done) if backwards else (at == 0 and done == 0),
                    not backwards and n - at <= done,
                    self._word(data, pos - step, width),
                    self._word(data, pos, width),
                )
                nxt, hits = self._step(memo, state, c, low, around)
            else:
                # the common step, looked up inline: the same key `_step` uses
                went = steps.get((state, c, low))
                nxt, hits = went if went is not None else self._step(memo, state, c, low, quiet)
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
            if memo.weight > Memo.WEIGHT:
                # the cache outgrew its bound within this run: carry on with a fresh one, the
                # current threads its first list
                memo, state = self._renew(
                    memo, state, (backwards, wide, nocase, dotall, every is not None)
                )
                steps, testing = memo.steps, memo.testing
        return found

    def _renew(self, memo: Memo, state: int, mode: tuple[bool, ...]) -> tuple[Memo, int]:
        keys = memo.states[state]
        fresh = self.memo[mode] = Memo()
        self._last = (mode, fresh)
        return fresh, fresh.state(keys)

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


__all__ = ["MAX_THREADS", "REACH", "Lanes", "Threads"]
