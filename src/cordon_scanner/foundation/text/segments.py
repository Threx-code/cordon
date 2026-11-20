"""A pattern read over a whole text, a segment at a time.

A reader that gave up on a text longer than some private cap of its own (`len(text) > 1_000_000: return`)
hid everything past the cap: a payload padded to just over the cap was never read. The scanner reads a
file up to `Limits.max_file_bytes` whole, and a detector must read what the scanner read.

`TextSegments.finditer` is `pattern.finditer(text)` made in bounded steps, with the same matches in the
same order. Each step searches one *owned* stretch of the text (`size` characters) and may look `overlap`
characters past it, so a match that starts in the stretch and is no longer than `overlap` is seen whole.
It uses the pattern's own `pos` and `endpos`, not a copy of the text: `^`, `\\b` and look-behind see the
characters before a stretch as they would in the whole, and every position is a position in `text`, so
nothing is shifted back and `FileContent.byte_offset` applies as before.

Two reasons to read in steps rather than in one call. A regular expression runs to its end without
returning to the interpreter, so a time limit cannot stop it part way: between steps it can. And the work
done for one stretch is bounded by `size + overlap` whatever the file's length.

The contract: `overlap` is at least the longest match the pattern can make (and any look-ahead it needs),
and the pattern does not match the empty string. A match longer than `overlap` that straddles the end of a
stretch is not found; a reader whose pattern has no bound must say so and not use this.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator
    from re import Match, Pattern

SEGMENT_CHARS: Final = 1 << 20
"""One owned stretch: a mebibyte of text."""

OVERLAP_CHARS: Final = 64 * 1024
"""How far past its stretch a step may look: the engine's own window overlap (`foundation/files/windows.py`)."""


class TextSegments:
    """`finditer(pattern, text)` and `search(pattern, text)` that read all of `text`."""

    @staticmethod
    def finditer(
        pattern: Pattern[str],
        text: str,
        *,
        size: int = SEGMENT_CHARS,
        overlap: int = OVERLAP_CHARS,
    ) -> Iterator[Match[str]]:
        """Every non-overlapping match of `pattern` in `text`, in order: what `pattern.finditer(text)` yields."""
        if size <= 0 or overlap < 0:
            raise ValueError("a segment needs a positive size and a non-negative overlap")
        length = len(text)
        if length <= size:
            yield from pattern.finditer(text)
            return
        resume = 0
        owned = 0
        while owned < length:
            stop = min(owned + size, length)
            reach = min(stop + overlap, length)
            for match in pattern.finditer(text, max(owned, resume), reach):
                if match.start() >= stop:
                    break
                resume = match.end()
                yield match
            owned = stop

    @staticmethod
    def search(
        pattern: Pattern[str],
        text: str,
        *,
        size: int = SEGMENT_CHARS,
        overlap: int = OVERLAP_CHARS,
    ) -> Match[str] | None:
        """The first match of `pattern` in `text`: what `pattern.search(text)` returns."""
        return next(TextSegments.finditer(pattern, text, size=size, overlap=overlap), None)


__all__ = ["OVERLAP_CHARS", "SEGMENT_CHARS", "TextSegments"]
