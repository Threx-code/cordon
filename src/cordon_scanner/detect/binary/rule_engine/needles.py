"""cordon-rule's anchor prefilter: which of a rule set's many anchors occur in a piece of data,
found in one pass over it (`scan.AnchorIndex` asks)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, ClassVar


class NeedleSet:
    """Which of many byte strings occur in a piece of data, in one pass over it.

    The needles' first `PREFIX` bytes become a trie, written as a regular expression of nested
    alternatives with no repetition, inside a lookahead: one pass of the `re` engine (C) stops
    only where some needle's prefix begins, and costs at most `PREFIX` steps per position. Each
    stop is then checked against the needles sharing that prefix. Few needles are looked for
    one at a time, where that is cheaper."""

    PREFIX: ClassVar[int] = 8
    #: Below this many needles, a `needle in data` each is cheaper than the pass.
    FEW: ClassVar[int] = 32

    def __init__(self, needles: Iterable[bytes]) -> None:
        self.needles = sorted(set(needles))
        self.by_prefix: dict[bytes, list[bytes]] = {}
        for n in self.needles:
            self.by_prefix.setdefault(n[: NeedleSet.PREFIX], []).append(n)
        self.finder: re.Pattern[bytes] | None = None
        if len(self.needles) >= NeedleSet.FEW and all(self.needles):
            trie: dict[int, Any] = {}
            for prefix in self.by_prefix:
                node = trie
                for b in prefix:
                    node = node.setdefault(b, {})
                node[-1] = {}
            self.finder = re.compile(b"(?=(" + NeedleSet._alternatives(trie) + b"))", re.DOTALL)

    @staticmethod
    def _alternatives(node: dict[int, Any]) -> bytes:
        """`node`'s subtree as alternatives; a needle ending here (key -1) is the empty one, last,
        so a longer prefix is preferred and the match names the longest prefix present."""
        parts = [
            re.escape(bytes((b,))) + (NeedleSet._alternatives(child) if child else b"")
            for b, child in sorted(node.items())
            if b != -1
        ]
        if -1 in node:
            parts.append(b"")
        return parts[0] if len(parts) == 1 else b"(?:" + b"|".join(parts) + b")"

    def present(self, data: bytes) -> set[bytes]:
        """The needles that occur in `data`."""
        if self.finder is None:
            return {n for n in self.needles if n in data}
        found: set[bytes] = set()
        left = len(self.needles)
        for m in self.finder.finditer(data):
            at, longest = m.start(), m.group(1)
            # every needle whose prefix is a prefix of the longest one present here
            for k in range(1, len(longest) + 1):
                for n in self.by_prefix.get(longest[:k], ()):
                    if n not in found and data.startswith(n, at):
                        found.add(n)
                        left -= 1
            if not left:
                break
        return found


__all__ = ["NeedleSet"]
