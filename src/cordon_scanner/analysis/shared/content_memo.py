"""Results of a pure analysis kept by the text they were worked out from.

A package can carry the same file many times -- vendored copies, a bundle under several names --
and more than one detector asks the same analysis of the same file. An analysis whose result is a
function of the text alone (the calls a JavaScript file makes, its source-to-sink flows) is worked
out once per process for each distinct text and handed back for every later ask.

Texts are told apart by a 128-bit digest of their UTF-8 bytes (lone surrogates encoded as they
stand), so a key never holds the text itself. The memo is bounded twice: by how many results it
keeps and by their total length, the oldest dropped first; a text shorter than `smallest` is
worked out every time, its analysis cheaper than the digest.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from collections.abc import Callable, Hashable, Sequence
from typing import Any, TypeVar

T = TypeVar("T")


class ContentMemo:
    """One analysis's results, by (the analysis's own key, the text's digest)."""

    def __init__(
        self, *, entries: int = 16384, weight: int = 1_000_000, smallest: int = 2048
    ) -> None:
        self.entries, self.weight, self.smallest = entries, weight, smallest
        self._kept: OrderedDict[tuple[Hashable, bytes], tuple[Any, ...]] = OrderedDict()
        self._held = 0

    @staticmethod
    def digest(text: str) -> bytes:
        return hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=16).digest()

    def get(self, key: Hashable, text: str, work: Callable[[], Sequence[T]]) -> list[T]:
        """`work()`'s result for `text`, worked out the first time and kept; a fresh list each
        time, so a caller may change the list it gets."""
        if len(text) < self.smallest:
            return list(work())
        slot = (key, ContentMemo.digest(text))
        kept = self._kept.get(slot)
        if kept is None:
            kept = tuple(work())
            self._kept[slot] = kept
            self._held += len(kept)
            while self._kept and (len(self._kept) > self.entries or self._held > self.weight):
                _, dropped = self._kept.popitem(last=False)
                self._held -= len(dropped)
        else:
            self._kept.move_to_end(slot)
        return list(kept)


__all__ = ["ContentMemo"]
