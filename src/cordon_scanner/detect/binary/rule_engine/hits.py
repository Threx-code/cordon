"""A string's matches in one file, kept compact, and the report built from them only when read.

A string can have up to `MAX_HITS` matches in a file, and a rule set many such strings: kept as Python
tuples with a slice of the data each, twenty hot strings on 100 MB of zeros held 4.4 GB. `Hits` keeps
a string's matches as two int64 arrays (start, length; 16 bytes a match) and reads as the sorted
list of (start, length) pairs a condition indexes (`#s`, `@s[i]`, `!s[i]`). `Match.strings` builds
its (offset, name, bytes) instances from them each time it is read, so the data is sliced only for a
match that is reported. Past `Hits.MOST` matches in one file, all strings together, the file is
refused (`TooManyMatches`), which the scan reports as the file failing to match, failing closed.
"""

from __future__ import annotations

from array import array
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, ClassVar, overload


class Hits(Sequence[tuple[int, int]]):
    """(start, length) of each match of one string, by start, in two int64 arrays."""

    __slots__ = ("lengths", "starts")

    #: The most matches one file may hold, all its strings together (16 bytes each: 512 MB).
    MOST: ClassVar[int] = 32_000_000

    def __init__(self, pairs: Iterable[tuple[int, int]] = ()) -> None:
        self.starts, self.lengths = array("q"), array("q")
        for start, length in pairs:
            self.starts.append(start)
            self.lengths.append(length)

    @staticmethod
    def of(hits: dict[int, int]) -> Hits:
        """A hunt's matches (start -> length), by start."""
        out = Hits()
        out.starts = array("q", sorted(hits))
        out.lengths = array("q", (hits[s] for s in out.starts))
        return out

    def __len__(self) -> int:
        return len(self.starts)

    @overload
    def __getitem__(self, i: int) -> tuple[int, int]: ...
    @overload
    def __getitem__(self, i: slice) -> list[tuple[int, int]]: ...
    def __getitem__(self, i: int | slice) -> tuple[int, int] | list[tuple[int, int]]:
        if isinstance(i, slice):
            return list(zip(self.starts[i], self.lengths[i], strict=True))
        return self.starts[i], self.lengths[i]

    def __iter__(self) -> Iterator[tuple[int, int]]:
        return zip(self.starts, self.lengths, strict=True)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Hits):
            return self.starts == other.starts and self.lengths == other.lengths
        if isinstance(other, list):
            return list(self) == other
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"Hits({list(self)!r})"


class Match:
    """What a matching rule reports: its name, tags, meta, and each string instance."""

    __slots__ = ("_data", "_hits", "_strings", "meta", "rule", "tags")

    def __init__(
        self,
        rule: str,
        tags: list[str],
        meta: dict[str, Any],
        strings: list[tuple[int, str, bytes]] | None = None,
        *,
        data: bytes = b"",
        hits: list[tuple[str, Sequence[tuple[int, int]]]] | None = None,
    ) -> None:
        self.rule, self.tags, self.meta = rule, tags, meta
        self._strings, self._data, self._hits = strings, data, hits or []

    @property
    def hits(self) -> list[tuple[str, Sequence[tuple[int, int]]]]:
        """Each string's matches as (name, its (offset, length) pairs), without the bytes."""
        return self._hits

    @property
    def strings(self) -> list[tuple[int, str, bytes]]:
        """Each instance as (offset, name, the bytes matched), by string then offset."""
        if self._strings is not None:
            return self._strings
        data = self._data
        return [(at, name, data[at : at + n]) for name, hits in self._hits for at, n in hits]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Match):
            return NotImplemented
        return (self.rule, self.tags, self.meta, self.strings) == (
            other.rule,
            other.tags,
            other.meta,
            other.strings,
        )

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"Match(rule={self.rule!r}, tags={self.tags!r}, meta={self.meta!r}, strings={self.strings!r})"


__all__ = ["Hits", "Match"]
