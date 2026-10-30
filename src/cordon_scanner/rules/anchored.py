"""A rule's matches in a file, found by trying the regex only where a match can start.

`regex.finditer(data)` tries the pattern at every byte. On a 10 MB bundle that is 0.2 to 0.4 s per
rule even when nothing matches, and 39 rules pass the literal gates on such a file: 10.3 s of the
12.6 s the capability matcher spent on one (review 98, item D, measured without a profiler).

Most patterns say where a match can start. `(?:\\bfetch\\s*\\()` begins with `fetch`; `\\b(?:curl)`
begins with `curl` after at most no bytes. A branch's anchor is the first run of literal bytes at its
top level, at least `SHORTEST` long, with everything before it of bounded width: then every match
of the branch starts between `low` and `high` bytes before an occurrence of the anchor. Finding the
anchor's occurrences is `bytes.find`, a C scan, and only the positions they allow are tried.

Exact, not approximate. `pattern.match(data, q)` makes the same attempt at `q` that `search` makes
when it reaches `q` -- the same string, so lookbehind, `\\b` and `^` see what they saw -- and the
whole alternation is tried there, so which branch wins is unchanged. A position no branch's anchor
allows is a position where no branch can match, so skipping it changes nothing; and the matches are
taken in order, each search resuming where the last match ended, as `finditer` does. Where that
cannot be shown -- a branch with no such anchor, a branch that can match empty, a file where the
anchors allow too many positions to be worth it -- the plan is None or declines, and `finditer` runs.
"""

from __future__ import annotations

import re
import re._compiler as sre_compile  # type: ignore[import-not-found]
import re._constants as sre  # type: ignore[import-not-found]
import re._parser as sre_parse  # type: ignore[import-not-found]
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(frozen=True, slots=True)
class Anchor:
    """One branch's anchor: its literal, how it is compared, and where a match starts from it."""

    literal: bytes
    folded: bool
    """Compared case-insensitively (the branch is IGNORECASE): looked for lower-cased."""
    low: int
    """The fewest bytes a match can have before the anchor."""
    high: int
    """The most."""


@dataclass(frozen=True, slots=True)
class Plan:
    """Where a pattern's matches can start: its anchored alternatives' anchors, and the rest of its
    alternatives as one pattern (`rest`) searched for directly, or None when every one is anchored."""

    anchors: tuple[Anchor, ...]
    rest: re.Pattern[bytes] | None = None


class AnchoredSearch:
    """`finditer`, trying the pattern only where an anchor allows a match to start."""

    SHORTEST: ClassVar[int] = 3
    """Anchors shorter than this occur too often to narrow anything."""

    WORTH: ClassVar[int] = 32
    """Candidate positions allowed per this many bytes of the file before `finditer` is cheaper."""

    @staticmethod
    def plan(pattern: re.Pattern[bytes]) -> Plan | None:
        """Where `pattern`'s matches can start, or None if no alternative of it says (then every
        position must be tried).

        When some top-level alternatives have anchors and some do not, the ones without are kept
        as one pattern of their own: one `search` of it finds the first place any of them can match,
        and only anchored positions before that place need trying."""
        try:
            tree = sre_parse.parse(pattern.pattern, pattern.flags)
        except (re.error, TypeError, ValueError, RecursionError):
            return None
        if tree.getwidth()[0] == 0:
            return None  # a pattern that can match empty: finditer's handling of those is its own
        flags = tree.state.flags
        found = AnchoredSearch._anchors(list(tree), flags, 0, 0)
        if found:
            return Plan(tuple(found))
        items = list(tree)
        if len(items) != 1 or items[0][0] is not sre.BRANCH:
            return None
        anchors: list[Anchor] = []
        rest: list[sre_parse.SubPattern] = []
        for alternative in items[0][1][1]:
            alternative_anchors = AnchoredSearch._anchors(list(alternative), flags, 0, 0)
            if alternative_anchors:
                anchors.extend(alternative_anchors)
            else:
                rest.append(alternative)
        if not anchors:
            return None
        try:
            remainder = sre_parse.SubPattern(tree.state, [(sre.BRANCH, (None, rest))])
            compiled = sre_compile.compile(remainder, pattern.flags)
        except (re.error, TypeError, ValueError, RecursionError):
            return None
        return Plan(tuple(anchors), compiled)

    @staticmethod
    def _anchors(
        items: list[tuple[object, object]], flags: int, low: int, high: int
    ) -> list[Anchor] | None:
        """Anchors for a sequence that starts `low` to `high` bytes into the match: the first
        literal run of `SHORTEST` bytes or more; or, for an alternation (a group, a repeat taken at
        least once), the anchors of every one of its alternatives, when each has some. None when
        nothing before an anchor has a bounded width, or no anchor is found."""
        index = 0
        while index < len(items):
            op, av = items[index]
            if op is sre.LITERAL:
                run: list[int] = []
                while index < len(items) and items[index][0] is sre.LITERAL:
                    run.append(items[index][1])  # type: ignore[arg-type]
                    index += 1
                if len(run) >= AnchoredSearch.SHORTEST:
                    literal = bytes(run)
                    folded = bool(flags & re.IGNORECASE)
                    return [Anchor(literal.lower() if folded else literal, folded, low, high)]
                low += len(run)
                high += len(run)
                continue
            inner = AnchoredSearch._inside(op, av, flags, low, high)
            if inner is not None:
                return inner
            least, most = sre_parse.SubPattern(sre_parse.State(), [items[index]]).getwidth()
            if most >= sre.MAXREPEAT:
                return None
            low += least
            high += most
            index += 1
        return None

    @staticmethod
    def _inside(op: object, av: object, flags: int, low: int, high: int) -> list[Anchor] | None:
        """Anchors from inside one item that every match passes through, at this offset."""
        if op is sre.SUBPATTERN:
            parts: tuple[Any, ...] = av  # type: ignore[assignment]
            add, remove, body = parts[1], parts[2], parts[3]
            return AnchoredSearch._anchors(list(body), (flags | add) & ~remove, low, high)
        if op is sre.BRANCH:
            found: list[Anchor] = []
            for alternative in av[1]:  # type: ignore[index]
                anchors = AnchoredSearch._anchors(list(alternative), flags, low, high)
                if not anchors:
                    return None  # one alternative without an anchor: any position may start it
                found.extend(anchors)
            return found
        if op in (sre.MAX_REPEAT, sre.MIN_REPEAT, sre.POSSESSIVE_REPEAT):
            repeat: tuple[Any, ...] = av  # type: ignore[assignment]
            least, body = repeat[0], repeat[2]
            if least >= 1:  # taken at least once, so its first pass starts here
                return AnchoredSearch._anchors(list(body), flags, low, high)
        if op is sre.ATOMIC_GROUP:
            return AnchoredSearch._anchors(list(av), flags, low, high)  # type: ignore[call-overload]
        return None

    @staticmethod
    def matches(
        pattern: re.Pattern[bytes],
        plan: Plan | None,
        data: bytes,
        lowered: bytes | None,
    ) -> Iterator[re.Match[bytes]]:
        """Exactly what `pattern.finditer(data)` yields, in order. `lowered` is `data.lower()` when
        the caller has it; it is made here if a case-insensitive anchor needs it."""
        starts = AnchoredSearch._starts(plan.anchors, data, lowered) if plan else None
        if plan is None or starts is None:
            yield from pattern.finditer(data)
            return
        resume = 0
        index = 0
        other = plan.rest.search(data, 0) if plan.rest is not None else None
        while True:
            # The first place an alternative without an anchor can match, from here on. No match of
            # the pattern starts before the next anchored candidate or this place, whichever is first.
            # Searched again only once a match has ended past it: until then it is still the first.
            if other is not None and other.start() < resume:
                other = plan.rest.search(data, resume)  # type: ignore[union-attr]
            limit = other.start() if other is not None else len(data) + 1
            found = None
            while index < len(starts) and starts[index] < limit:
                start = starts[index]
                index += 1
                if start < resume:
                    continue
                found = pattern.match(data, start)
                if found is not None:
                    break
            if found is None and other is not None:
                # Nothing anchored matched before it, and an alternative matches here: the whole
                # pattern, tried here, gives the match `search` would (its alternatives in order).
                found = pattern.match(data, limit)
            if found is None:
                return
            yield found
            resume = found.end()
            while index < len(starts) and starts[index] < resume:
                index += 1

    @staticmethod
    def _starts(plan: tuple[Anchor, ...], data: bytes, lowered: bytes | None) -> list[int] | None:
        """Every position a match can start at, ascending; None when there are too many."""
        budget = len(data) // AnchoredSearch.WORTH + 64
        starts: set[int] = set()
        for anchor in plan:
            haystack = data
            if anchor.folded:
                if lowered is None:
                    lowered = data.lower()
                haystack = lowered
            at = haystack.find(anchor.literal)
            while at >= 0:
                starts.update(range(max(0, at - anchor.high), at - anchor.low + 1))
                if len(starts) > budget:
                    return None
                at = haystack.find(anchor.literal, at + 1)
        return sorted(starts)


__all__ = ["Anchor", "AnchoredSearch", "Plan"]
