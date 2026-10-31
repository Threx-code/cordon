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

if TYPE_CHECKING:
    from cordon_scanner.detect.binary.rule_engine.scan import Search, _Hunt
    from cordon_scanner.detect.binary.rule_engine.search_parts import AnchorAt, Event

Source = Callable[[], Iterator["Event"]]


class Streams:
    #: A string is streamed when one of its anchors occurs, or one of its anchorless parts may start,
    #: more often than this (counted without overlaps, in C): below it the list is cheaper.
    ABOVE: ClassVar[int] = 262_144

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
            if seen.get(needle) is None and data.count(needle) > Streams.ABOVE:
                return True
        if search.folds:
            lowered = seen.get(("lowered",))
            if lowered is None:
                lowered = seen[("lowered",)] = data.lower()
            for folded, _, _ in search.folds:
                if seen.get(("folded", folded)) is None and lowered.count(folded) > Streams.ABOVE:
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
            gates = search.gates(data, needle, owners) if starts is None else None
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

    @staticmethod
    def merged(sources: list[tuple[Source, frozenset[int]]]) -> Iterator[Event]:
        return heapq.merge(*(s() for s, _ in sources), key=lambda e: (e[0], e[1], e[2]))


__all__ = ["Streams"]
