"""Where a pattern can start: the literal runs a program must contain, chosen so the search looks for
those with a fast byte search and starts the threads only where one is found.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.pattern import (
    ANY,
    COUNT,
    EITHER,
    LIT,
    MASKED,
    PLUS,
    SEQ,
    Bytes,
    Term,
)

#: An anchor is at most this many bytes.
ANCHOR = 4

#: The best score an anchor can have.
TOP_SCORE = 255


class Anchor:
    """A run of at most `ANCHOR` bytes a string's matches must contain, `back` bytes into the
    string; `term` is the pattern term it begins at (None for a plain text string)."""

    __slots__ = ("back", "data", "masks", "term")

    def __init__(self, data: list[int], masks: list[int], back: int, term: Term | None) -> None:
        self.data, self.masks, self.back, self.term = data, masks, back, term

    def copy(self) -> Anchor:
        return Anchor(list(self.data), list(self.masks), self.back, self.term)


class Anchors:
    """Which anchors a pattern's search looks for. Each candidate run is scored for how rarely
    it should occur in data (`score`): longer, with fewer wildcards and fewer common bytes, more
    varied. Alternatives need an anchor in every branch; the best-scoring choice wins."""

    COMMON: ClassVar[frozenset[int]] = frozenset((0x00, 0x20, 0xCC, 0xFF))
    FILLER: ClassVar[frozenset[int]] = frozenset((0x00, 0x20, 0x90, 0xCC, 0xFF))

    @staticmethod
    def score(data: list[int], masks: list[int]) -> int:
        points = 0
        distinct: set[int] = set()
        for b, m in zip(data, masks, strict=True):
            if m == 0:
                points -= 10
            elif m in (0x0F, 0xF0):
                points += 4
            elif m == 0xFF:
                if b in Anchors.COMMON:
                    points += 12
                elif 0x61 <= Bytes.LOWER[b] <= 0x7A:
                    points += 18
                else:
                    points += 20
                distinct.add(b)
        if len(distinct) == 1 and distinct <= Anchors.FILLER:
            points -= 10 * len(data)
        else:
            points += 2 * len(distinct)
        return TOP_SCORE - 22 * ANCHOR + points

    @staticmethod
    def trim(data: list[int], masks: list[int]) -> tuple[list[int], list[int], int]:
        """Wildcards cut from both ends; a run with as many wildcards as known bytes kept to its
        first byte. Returns the run and how many bytes were cut from its front."""
        left = 0
        while left < len(masks) and masks[left] == 0:
            left += 1
        right = len(masks)
        while right > left and masks[right - 1] == 0:
            right -= 1
        if right == left:
            return [], [], 0
        known = sum(1 for m in masks[left:right] if m == 0xFF)
        unknown = sum(1 for m in masks[left:right] if m == 0)
        if unknown >= known:
            right = left + 1
        return data[left:right], masks[left:right], left

    def __init__(self) -> None:
        # the group leaves are being added to: ["any", members]; members are leaves
        # ["run", data, masks, terms] and ["all", group, group] for alternatives
        self.group: list[Any] = ["any", []]
        self.run: list[Term] = []
        self.best: tuple[list[int], list[int], list[Term]] = ([], [], [])
        self.best_score = -1

    @staticmethod
    def of(root: Term) -> tuple[list[Anchor], int]:
        """The anchors chosen for a pattern tree, wildcards expanded, and the worst score."""
        a = Anchors()
        top = a.group
        a._to(top)
        a._walk(root)
        a._to(top)
        chosen, worst = Anchors._choose(top)
        return Anchors._expand(chosen), worst

    def _to(self, group: list[Any]) -> None:
        """Closes the run being collected into the current group, then collects into `group`."""
        if self.run:
            data = [t.value & 0xFF for t in self.run]
            masks = [t.mask & 0xFF for t in self.run]
            cut_data, cut_masks, cut = Anchors.trim(data, masks)
            if Anchors.score(cut_data, cut_masks) > self.best_score:
                leaf = ["run", cut_data, cut_masks, self.run[cut:]]
            else:
                leaf = ["run", *self.best]
            self.group[1].append(leaf)
            self.run = []
        self.group = group
        self.best_score = -1

    def _take(self, t: Term) -> None:
        if len(self.run) < ANCHOR:
            self.run.append(t)
            self.best = ([x.value & 0xFF for x in self.run], [x.mask & 0xFF for x in self.run],
                         list(self.run))  # fmt: skip
        elif self.best_score < TOP_SCORE:
            data = [x.value & 0xFF for x in self.run]
            masks = [x.mask & 0xFF for x in self.run]
            cut_data, cut_masks, cut = Anchors.trim(data, masks)
            s = Anchors.score(cut_data, cut_masks)
            if s > self.best_score:
                self.best = (cut_data, cut_masks, self.run[cut : cut + len(cut_data)])
                self.best_score = s
            self.run = [*self.run[1:], t]

    def _walk(self, t: Term) -> None:
        k = t.kind
        if k in (LIT, MASKED, ANY):
            self._take(t)
        elif k == SEQ:
            for kid in t.kids:
                self._walk(kid)
        elif k == EITHER:
            here = self.group
            left: list[Any] = ["any", []]
            right: list[Any] = ["any", []]
            here[1].append(["all", left, right])
            self._to(left)
            self._walk(t.kids[0])
            self._to(right)
            self._walk(t.kids[1])
            self._to(here)
        elif k == PLUS:
            self._walk(t.kids[0])
            self._to(self.group)
        elif k == COUNT:
            for _ in range(min(t.lo, ANCHOR)):
                self._walk(t.kids[0])
            self._to(self.group)
        else:
            self._to(self.group)

    @staticmethod
    def _choose(node: list[Any]) -> tuple[list[Anchor], int]:
        if node[0] == "run":
            data, masks, cut = Anchors.trim(node[1], node[2])
            if not data:
                return [], 0
            return [Anchor(data, masks, 0, node[3][cut])], Anchors.score(data, masks)
        if node[0] == "any":
            best: list[Anchor] = []
            top = 0
            for member in node[1]:
                chosen, s = Anchors._choose(member)
                if s > top:
                    best, top = chosen, s
                if top == TOP_SCORE:
                    break
            return best, top
        out: list[Anchor] = []
        worst = TOP_SCORE
        for member in node[1:]:
            chosen, s = Anchors._choose(member)
            worst = min(worst, s)
            out = chosen + out
        return out, worst

    @staticmethod
    def _expand(anchors: list[Anchor]) -> list[Anchor]:
        """Every wildcard byte replaced by each value it allows, in place in the list."""
        k = 0
        while k < len(anchors):
            a = anchors[k]
            widened = False
            for i, m in enumerate(a.masks):
                if m == 0xFF:
                    continue
                if m == 0:
                    lo, hi, step = 0, 255, 1
                elif m == 0x0F:
                    lo, hi, step = a.data[i], a.data[i] | 0xF0, 0x10
                elif m == 0xF0:
                    lo, hi, step = a.data[i], a.data[i] | 0x0F, 1
                else:
                    continue
                widened = True
                a.data[i], a.masks[i] = lo, 0xFF
                more = []
                for v in range(lo + step, hi + 1, step):
                    b = a.copy()
                    b.data[i] = v
                    more.append(b)
                anchors[k + 1 : k + 1] = more
            if not widened:
                k += 1
        return anchors

    @staticmethod
    def of_text(text: bytes) -> tuple[Anchor, int]:
        """A text string's anchor: its best-scoring `ANCHOR`-byte window."""
        first = list(text[:ANCHOR])
        best = Anchor(first, [0xFF] * len(first), 0, None)
        top = Anchors.score(best.data, best.masks)
        i = ANCHOR
        while i < len(text) and top < TOP_SCORE:
            window = list(text[i - ANCHOR + 1 : i + 1])
            s = Anchors.score(window, [0xFF] * ANCHOR)
            if s > top:
                best, top = Anchor(window, [0xFF] * ANCHOR, i - ANCHOR + 1, None), s
            i += 1
        return best, top

    @staticmethod
    def wide(anchors: list[Anchor]) -> list[Anchor]:
        out: list[Anchor] = []
        for a in anchors:
            data = [x for b in a.data for x in (b, 0)][:ANCHOR]
            out.insert(0, Anchor(data, [0xFF] * len(data), a.back * 2, a.term))
        return out

    @staticmethod
    def cases(anchors: list[Anchor]) -> list[Anchor]:
        """Every other-case spelling of each anchor's letters (the anchor itself not included)."""
        out: list[Anchor] = []
        for a in anchors:
            made: list[list[int]] = []
            Anchors._respell(a.data, 0, made)
            for data in made:
                out.insert(0, Anchor(data, [0xFF] * len(data), a.back, a.term))
        return out

    @staticmethod
    def _respell(data: list[int], at: int, made: list[list[int]]) -> None:
        if at + 1 < len(data):
            Anchors._respell(data, at + 1, made)
        c = data[at] if at < len(data) else -1
        if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
            other = list(data)
            other[at] = c ^ 0x20
            made.append(other)
            if at + 1 < len(data):
                Anchors._respell(other, at + 1, made)

    @staticmethod
    def xored(anchors: list[Anchor], lo: int, hi: int) -> list[Anchor]:
        out: list[Anchor] = []
        for a in anchors:
            for key in range(lo, hi + 1):
                data = [b ^ key for b in a.data][:ANCHOR]
                out.insert(0, Anchor(data, [0xFF] * len(data), a.back, a.term))
        return out


__all__ = ["ANCHOR", "TOP_SCORE", "Anchor", "Anchors"]
