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

A branch with no anchor but the shape `literal [^\n]* tail` (`>>[^\n]*\\.bashrc\b`) is searched a
line at a time (`Monotone`): once it fails at one occurrence of the literal, it fails at every later
occurrence on that line, since the `[^\n]*` from the earlier one reaches every position the later
one reaches and the tail is the same test at the same place. `finditer` tries each occurrence and
scans to the line's end from each: quadratic in a line of many `>>` (review 98, R6). One attempt a
line is linear. The one exception is written in: an optional run of blanks ending in a newline
between the literal and the `[^\n]*` (`(?>\\s*\n)?`) lets the last occurrence on a line, when only
blanks follow it, continue onto the next line; that one is tried too.
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
class Monotone:
    """One alternative shaped `literal [^\n]* tail`, searched a line at a time: see the module
    docstring. `pattern` is that alternative alone, tried at an occurrence of `literal`."""

    literal: bytes
    folded: bool
    """Compared case-insensitively (the alternative is IGNORECASE): looked for lower-cased."""
    continuation: bool
    """An optional run of blanks ending in a newline follows the literal, so the last occurrence
    on a line, when only blanks follow it, can match on the line after."""
    pattern: re.Pattern[bytes]


@dataclass(frozen=True, slots=True)
class Plan:
    """Where a pattern's matches can start: its anchored alternatives' anchors, its line-monotone
    alternatives (`monotone`), and the rest of its alternatives as one pattern (`rest`) searched
    for directly, or None when none is left."""

    anchors: tuple[Anchor, ...]
    rest: re.Pattern[bytes] | None = None
    monotone: tuple[Monotone, ...] = ()
    anchored: re.Pattern[bytes] | None = None
    """The anchored alternatives as one pattern, searched for directly when the file allows too
    many candidate positions: with a line-monotone alternative in the plan, the raw pattern is
    never run whole, since that alternative's quadratic line would come back through it."""


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
            alone = AnchoredSearch._monotone(tree, flags, pattern.flags)
            return None if alone is None else Plan((), None, (alone,))
        anchors: list[Anchor] = []
        monotone: list[Monotone] = []
        rest: list[sre_parse.SubPattern] = []
        anchored: list[sre_parse.SubPattern] = []
        for alternative in items[0][1][1]:
            alternative_anchors = AnchoredSearch._anchors(list(alternative), flags, 0, 0)
            if alternative_anchors:
                anchors.extend(alternative_anchors)
                anchored.append(alternative)
                continue
            line_wise = AnchoredSearch._monotone(alternative, flags, pattern.flags)
            if line_wise is not None:
                monotone.append(line_wise)
            else:
                rest.append(alternative)
        if not anchors and not monotone:
            return None
        try:
            compiled = AnchoredSearch._together(rest, tree.state, pattern.flags)
            whole = AnchoredSearch._together(
                anchored if monotone else [], tree.state, pattern.flags
            )
        except (re.error, TypeError, ValueError, RecursionError):
            return None
        return Plan(tuple(anchors), compiled, tuple(monotone), whole)

    @staticmethod
    def _together(
        alternatives: list[sre_parse.SubPattern], state: sre_parse.State, flags: int
    ) -> re.Pattern[bytes] | None:
        """`alternatives` as one compiled alternation; None for none."""
        if not alternatives:
            return None
        joined = sre_parse.SubPattern(state, [(sre.BRANCH, (None, alternatives))])
        return sre_compile.compile(joined, flags)  # type: ignore[no-any-return]

    @staticmethod
    def _monotone(
        alternative: sre_parse.SubPattern, flags: int, pattern_flags: int
    ) -> Monotone | None:
        """`alternative` as a `Monotone` when it has the shape `literal [^\n]* tail`, with an
        optional run of blanks ending in a newline between the literal and the `[^\n]*`; None
        otherwise. The literal holds no newline, so its occurrences sit on one line each."""
        items = list(alternative)
        index, run = 0, []
        while index < len(items) and items[index][0] is sre.LITERAL:
            run.append(items[index][1])
            index += 1
        if not run or 10 in run:
            return None
        continuation = index < len(items) and AnchoredSearch._blanks_then_newline(items[index])
        if continuation:
            index += 1
        if index >= len(items) or not AnchoredSearch._rest_of_line(items[index]):
            return None
        try:
            alone = sre_compile.compile(
                sre_parse.SubPattern(alternative.state, items), pattern_flags
            )
        except (re.error, TypeError, ValueError, RecursionError):
            return None
        folded = bool(flags & re.IGNORECASE)
        literal = bytes(run)
        return Monotone(literal.lower() if folded else literal, folded, continuation, alone)

    @staticmethod
    def _rest_of_line(item: tuple[object, object]) -> bool:
        """`[^\n]*`, greedy or lazy."""
        op, av = item
        if op not in (sre.MAX_REPEAT, sre.MIN_REPEAT):
            return False
        repeat: tuple[Any, ...] = av  # type: ignore[assignment]
        least, most, body = repeat
        if least != 0 or most != sre.MAXREPEAT or len(body) != 1:
            return False
        inner_op, inner_av = body[0]
        if inner_op is sre.NOT_LITERAL:
            return bool(inner_av == 10)
        return bool(
            inner_op is sre.IN and list(inner_av) == [(sre.NEGATE, None), (sre.LITERAL, 10)]
        )

    @staticmethod
    def _blanks_then_newline(item: tuple[object, object]) -> bool:
        """An optional group (`(?:...)?`, atomic or not) of blank runs and newlines holding at least
        one newline outright: taken, it covers the rest of the literal's line and at least one
        line break, so nothing else on that line can start a match."""
        op, av = item
        if op is not sre.MAX_REPEAT:
            return False
        optional: tuple[Any, ...] = av  # type: ignore[assignment]
        least, most, body = optional
        if least != 0 or most != 1 or len(body) != 1:
            return False
        group_op, group_av = body[0]
        if group_op is sre.SUBPATTERN:
            inner = list(group_av[3])
        elif group_op is sre.ATOMIC_GROUP:
            inner = list(group_av)
        else:
            return False
        newline = False
        for inner_op, inner_av in inner:
            if inner_op is sre.LITERAL and inner_av == 10:
                newline = True
            elif inner_op in (sre.MAX_REPEAT, sre.MIN_REPEAT, sre.POSSESSIVE_REPEAT):
                run = inner_av[2]
                if list(run) != [(sre.IN, [(sre.CATEGORY, sre.CATEGORY_SPACE)])]:
                    return False
            else:
                return False
        return newline

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
        if plan is None or (starts is None and not plan.monotone):
            yield from pattern.finditer(data)
            return
        searched = [plan.rest] if plan.rest is not None else []
        if starts is None:
            # Too many anchored candidates to try one by one: the anchored alternatives are
            # searched for directly instead, and the line-monotone ones still go a line at a time.
            starts = []
            searched.append(plan.anchored)  # type: ignore[arg-type]
        if lowered is None and any(m.folded for m in plan.monotone):
            lowered = data.lower()
        resume = 0
        index = 0
        others = [(direct, direct.search(data, 0)) for direct in searched]
        line_wise = [AnchoredSearch._next_line_wise(m, data, lowered, 0) for m in plan.monotone]
        while True:
            # The first place an alternative searched for directly can match, from here on. No match
            # of the pattern starts before the next anchored candidate or this place, whichever is
            # first. Searched again only once a match has ended past it: until then it is still
            # the first.
            limit = len(data) + 1
            for which, (direct, other) in enumerate(others):
                if other is not None and other.start() < resume:
                    other = direct.search(data, resume)
                    others[which] = (direct, other)
                if other is not None and other.start() < limit:
                    limit = other.start()
            for which, at in enumerate(line_wise):
                if at is not None and at < resume:
                    at = AnchoredSearch._next_line_wise(plan.monotone[which], data, lowered, resume)
                    line_wise[which] = at
                if at is not None and at < limit:
                    limit = at
            found = None
            while index < len(starts) and starts[index] < limit:
                start = starts[index]
                index += 1
                if start < resume:
                    continue
                found = pattern.match(data, start)
                if found is not None:
                    break
            if found is None and limit <= len(data):
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
    def _next_line_wise(
        line_wise: Monotone, data: bytes, lowered: bytes | None, pos: int
    ) -> int | None:
        """The first position at or past `pos` where `line_wise` matches, or None: one attempt per
        line, at the first occurrence of the literal from `pos` on, plus the last occurrence on
        that line when only blanks follow it (the continuation onto the next line)."""
        haystack = lowered if line_wise.folded and lowered is not None else data
        literal, width = line_wise.literal, len(line_wise.literal)
        while True:
            at = haystack.find(literal, pos)
            if at < 0:
                return None
            if line_wise.pattern.match(data, at) is not None:
                return at
            newline = data.find(b"\n", at + width)
            if newline < 0:
                return None  # the last line: no later occurrence on it can do better
            if line_wise.continuation:
                last = haystack.rfind(literal, at + width, newline)
                if last >= 0:
                    tail = data[last + width : newline]
                    if (not tail or tail.isspace()) and line_wise.pattern.match(data, last):
                        return last
            pos = newline + 1

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


__all__ = ["Anchor", "AnchoredSearch", "Monotone", "Plan"]
