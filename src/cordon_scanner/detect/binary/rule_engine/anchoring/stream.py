"""A string's anchor events as sorted streams, merged and consumed in order, so a file with millions
of places to try costs no more memory than the matches found (`Search.find` on a large file).

`Search.find` collects one event per anchor occurrence (and per place an anchorless part may start),
sorts them all by (end, -length, -order) and hunts through them in that order until the matches are
counted or `MAX_HITS` is reached. Here each source -- one anchor and owner, one gated owner, one
case-folded anchor, one anchorless part -- yields its events already in that order, lazily; a stable
merge of the sources in the order the list was built gives the same sequence the stable sort gives
(ties fall to the earlier source, as they fell to the earlier insertion), and the hunt stops pulling
once it is full. What the hunt reads of the whole list is only whether a part has more than
`_Hunt.BUSY` occurrences, which a count of at most `BUSY + 1` per source answers exactly; a string
whose matches are worked out from all its offsets at once (a chain, `_Hunt._chained`) is not
streamed. test_stream holds the streamed and the whole-list hunts to the same matches.
"""

from __future__ import annotations

import heapq
from collections.abc import Callable, Iterator
from functools import partial
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places

if TYPE_CHECKING:
    from cordon_scanner.detect.binary.rule_engine.scan import Search, _Hunt
    from cordon_scanner.detect.binary.rule_engine.search_parts import AnchorAt, Event

Source = Callable[[], Iterator["Event"]]


class Streams:
    #: A string is streamed when one of its anchors occurs, or one of its anchorless parts may start,
    #: more often than this (counted without overlaps, in C): below it the list is cheaper.
    ABOVE: ClassVar[int] = 262_144

    @staticmethod
    def lag(search: Search) -> int:
        """How far an event's offset may lie before its end (an anchor's length and lead)."""
        backs = [
            length + anchor[1]
            for _, length, owners in (search.needles or [])
            for _, _, anchor in owners
        ]
        backs += [
            length + anchor[1]
            for _, length, spellings in search.folds
            for owners in spellings.values()
            for _, _, anchor in owners
        ]
        return max(backs, default=0)

    @staticmethod
    def gates(
        search: Search,
        data: bytes,
        needle: bytes,
        owners: list[tuple[int, int, AnchorAt]],
        seen: dict[Any, Any],
    ) -> list[Any] | None:
        """Each owner's forward gate, where a common anchor's events come from them (`_gated`),
        else None: a pattern part, not `plain`, one byte wide, more than `GATED` occurrences."""
        f = search.flags
        if "wide" in f or "xor" in f or "base64" in f or "base64wide" in f or f.get("plain"):
            return None
        if Streams.count(data, needle, seen) <= type(search).GATED:
            return None
        nocase, dotall = "nocase" in f, "dotall" in f
        gates = []
        for _, p, anchor in owners:
            part = search.parts[p]
            if part.text is not None or anchor[2] is None:
                return None
            gate = part.gate(anchor[2], nocase, dotall)
            if gate is None:
                return None
            gates.append(gate)
        return gates

    @staticmethod
    def count(data: bytes, needle: bytes, seen: dict[Any, Any], *, folded: bool = False) -> int:
        """How often `needle` occurs in `data` without overlaps (in C), worked out once a file and
        kept in `seen`, which every string searched there shares."""
        key = ("count", folded, needle)
        held = seen.get(key)
        if held is None:
            held = seen[key] = data.count(needle)
        return int(held)

    @staticmethod
    def dense(data: bytes, needle: bytes, seen: dict[Any, Any], folded: bool) -> bool:
        """Whether `needle` occurs more than `ABOVE` times without overlaps (`count`'s answer),
        read with its offsets in one pass where they are few: up to `ABOVE` overlapping ones (and
        no more than the file's budget holds) are kept in `seen` for the find that follows
        (`Search.located`), and their count without overlaps is `count`'s. Past that, `count`
        itself decides, and the find reads the offsets as it did."""
        key = ("count", folded, needle)
        if seen.get(key) is None:
            # never more offsets than the find could keep: past the file's budget it refuses
            # them (`Places.occurrences`), so holding more would only cost memory
            keep = min(Streams.ABOVE, Places.MOST, Places.budget(seen)[0])
            found: list[int] = []
            at = data.find(needle)
            while at >= 0 and len(found) <= keep:
                found.append(at)
                at = data.find(needle, at + 1)
            if len(found) <= keep:
                apart, end = 0, 0
                for at in found:  # leftmost without overlaps, as bytes.count counts
                    if at >= end:
                        apart, end = apart + 1, at + len(needle)
                seen[key] = apart
                seen[("pending", folded, needle)] = found
        return Streams.count(data, needle, seen, folded=folded) > Streams.ABOVE

    @staticmethod
    def finds(data: bytes, needle: bytes) -> Iterator[int]:
        """Every offset `needle` begins at, overlapping ones included, one at a time."""
        at = data.find(needle)
        while at >= 0:
            yield at
            at = data.find(needle, at + 1)

    @staticmethod
    def wanted(search: Search, data: bytes, seen: dict[Any, Any]) -> bool:
        """Whether `search` should be streamed over `data`."""
        for needle, _, _ in search.needles or ():
            if seen.get(needle) is None and Streams.dense(data, needle, seen, False):
                return True
        if search.folds:
            lowered = seen.get(("lowered",))
            if lowered is None:
                lowered = seen[("lowered",)] = data.lower()
            for folded, _, _ in search.folds:
                if seen.get(("folded", folded)) is None and Streams.dense(
                    lowered, folded, seen, True
                ):
                    return True
        return bool(search.zeros) and len(data) > Streams.ABOVE

    @staticmethod
    def exact(
        starts: Iterator[int], length: int, owner: tuple[int, int, AnchorAt]
    ) -> Iterator[Event]:
        order, p, anchor = owner
        back = length + anchor[1]
        for s in starts:
            if back <= s + length:
                yield (s + length, -length, -order, p, anchor, s + length - back)

    @staticmethod
    def gated(
        data: bytes, needle: bytes, length: int, owner: tuple[int, int, AnchorAt], gate: Any
    ) -> Iterator[Event]:
        order, p, anchor = owner
        lead = anchor[1]
        for found in gate.finditer(data):
            offset = found.start()
            at = offset + lead
            if data.startswith(needle, at):
                yield (at + length, -length, -order, p, anchor, offset)

    @staticmethod
    def folded(
        data: bytes, starts: Iterator[int], length: int, spellings: dict[bytes, Any]
    ) -> Iterator[Event]:
        for s in starts:
            owners = spellings[data[s : s + length]]
            here = []
            for order, p, anchor in owners:
                back = length + anchor[1]
                if back <= s + length:
                    here.append((s + length, -length, -order, p, anchor, s + length - back))
            here.sort(key=lambda e: (e[0], e[1], e[2]))
            yield from here

    @staticmethod
    def sources(
        search: Search, data: bytes, seen: dict[Any, Any], hunt: _Hunt
    ) -> list[tuple[Source, frozenset[int]]]:
        """Each source of `search`'s events over `data`, in the order `Search.find` lists them,
        with the parts its events can belong to."""
        out: list[tuple[Source, frozenset[int]]] = []
        for needle, length, owners in search.needles or ():
            starts = seen.get(needle)
            gates = Streams.gates(search, data, needle, owners, seen) if starts is None else None
            if gates is not None:
                out += [
                    (partial(Streams.gated, data, needle, length, o, g), frozenset({o[1]}))
                    for o, g in zip(owners, gates, strict=True)
                ]
                continue
            for owner in owners:
                out.append(
                    (
                        partial(Streams.exact_of, data, needle, starts, length, owner),
                        frozenset({owner[1]}),
                    )
                )
        for folded, length, spellings in search.folds:
            starts = seen.get(("folded", folded))
            can = frozenset(q for owners in spellings.values() for _, q, _ in owners)
            out.append(
                (
                    partial(
                        Streams.folded_of,
                        data,
                        seen[("lowered",)],
                        folded,
                        starts,
                        length,
                        spellings,
                    ),
                    can,
                )
            )
        for order, p, anchor in search.zeros:
            out.append((partial(Streams.anchorless, hunt, order, p, anchor), frozenset({p})))
        return out

    @staticmethod
    def exact_of(
        data: bytes,
        needle: bytes,
        starts: list[int] | None,
        length: int,
        owner: tuple[int, int, AnchorAt],
    ) -> Iterator[Event]:
        found = Streams.finds(data, needle) if starts is None else iter(starts)
        return Streams.exact(found, length, owner)

    @staticmethod
    def folded_of(
        data: bytes, lowered: bytes, folded: bytes, starts: list[int] | None, length: int,
        spellings: dict[bytes, Any],
    ) -> Iterator[Event]:  # fmt: skip
        found = Streams.finds(lowered, folded) if starts is None else iter(starts)
        return Streams.folded(data, found, length, spellings)

    @staticmethod
    def anchorless(hunt: _Hunt, order: int, p: int, anchor: AnchorAt) -> Iterator[Event]:
        for at in hunt.starts(p, lazy=True):
            yield (at, 0, -order, p, anchor, at)

    @staticmethod
    def busy(sources: list[tuple[Source, frozenset[int]]], cap: int) -> tuple[dict[int, int], int]:
        """How many events each part has, and in all, each part counted to at most `cap` per
        source (every comparison the hunt makes with them is with less than `cap`): a source is
        read until each part it can give has `cap` events, or to its end."""
        parts: dict[int, int] = {}
        total = 0
        for source, can in sources:
            counts: dict[int, int] = {}
            full = 0
            for event in source():
                q = event[3]
                c = counts.get(q, 0)
                if c < cap:
                    counts[q] = c + 1
                    if c + 1 == cap:
                        full += 1
                        if full >= len(can):
                            break
            for q, c in counts.items():
                parts[q] = parts.get(q, 0) + c
                total += c
        return parts, total

    #: The width of the windows a chain string's anchors are handed to its matcher in.
    WINDOW: ClassVar[int] = 1 << 20

    @staticmethod
    def offsets(events: Iterator[Event], lag: int, n: int) -> Iterator[int]:
        """The distinct offsets of `events`, ascending. An event's offset is its end less at most
        `lag`, and the events come by end, so an offset below the current end less `lag` can come
        no more: it is given then, and only the offsets in that span are held."""
        held: list[int] = []
        last = -1
        for e in events:
            if e[5] < n:
                heapq.heappush(held, e[5])
            while held and held[0] < e[0] - lag:
                q = heapq.heappop(held)
                if q != last:
                    yield q
                    last = q
        while held:
            q = heapq.heappop(held)
            if q != last:
                yield q
                last = q

    @staticmethod
    def chained(chain: Any, data: bytes, anchors: Iterator[int], *, backward: bool, nocase: bool,
                dotall: bool, deadline: float | None) -> Iterator[tuple[int, int]]:  # fmt: skip
        """A chain string's matches from its anchors, a window of `WINDOW` offsets at a time, by
        start: what `Chain.matches` gives over all of them at once.

        It is exact because a chain's answer for an anchor is what a run from it gives, and a run
        reads at most `REACH` bytes on from the anchor and, backward, at most `REACH` back: the
        anchors of [a, b) are answered over the data from a - REACH to b + 2 REACH, as over the whole.
        A match starting in [a, b) comes from an anchor in [a, b + REACH] (a start is never past its
        anchor, nor more than `REACH` before it), and where several anchors' backward runs reach one
        start the last keeps it; so each window is given every anchor to b + REACH, and keeps only
        the starts in [a, b)."""
        from cordon_scanner.detect.binary.rule_engine.threads import REACH

        n, window = len(data), Streams.WINDOW
        pending: list[int] = []
        source = iter(anchors)
        exhausted = False
        a = 0
        while True:
            if not pending and not exhausted:
                nxt = next(source, None)
                if nxt is None:
                    exhausted = True
                else:
                    pending.append(nxt)
            if not pending:
                return
            a = max(a, pending[0] - REACH)
            b = a + window
            while not exhausted and pending[-1] < b + REACH:
                nxt = next(source, None)
                if nxt is None:
                    exhausted = True
                else:
                    pending.append(nxt)
            base, end = max(0, a - REACH), min(n, b + 2 * REACH)
            given = [q - base for q in pending if q <= b + REACH]
            found = chain.matches(data[base:end], given, backward=backward, nocase=nocase,
                                  dotall=dotall, deadline=deadline)  # fmt: skip
            for start, length in found or ():
                if a <= start + base < b:
                    yield start + base, length
            pending = [q for q in pending if q >= b]
            a = b

    @staticmethod
    def merged(sources: list[tuple[Source, frozenset[int]]]) -> Iterator[Event]:
        return heapq.merge(*(s() for s, _ in sources), key=lambda e: (e[0], e[1], e[2]))


__all__ = ["Streams"]
