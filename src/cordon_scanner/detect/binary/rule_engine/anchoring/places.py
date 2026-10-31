"""How many places to try one file may hold for a rule file's strings (`Places.MOST`, in all), and
the refusal past it (`Unbounded`): the whole-list hunt's bound, which a file padded on purpose cannot
use to exhaust the scan's memory (the streamed hunt, `rule_engine.anchoring.stream`, holds none of them)."""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.pattern import Unbounded


class Places:
    #: The most anchor occurrences, or places to run an anchorless part from, one string reads in
    #: one file. Past it the file is refused for the rule file (a `RunError`, which the scan reports
    #: as the rule file being unavailable for that file) instead of being built in memory: one
    #: hostile file of a common anchor (100 MB of zeros for `{ 00 00 00 00 }`) cannot exhaust the
    #: scan's memory. Below it every answer is the one an unbounded search gives.
    MOST: ClassVar[int] = 8_000_000

    @staticmethod
    def occurrences(data: bytes, needle: bytes, budget: list[int] | None = None) -> list[int]:
        """Every offset `needle` begins at, overlapping ones included; an `Unbounded` past
        `Places.MOST` of them, or past what is left of the file's `budget` (`Places.budget`),
        which this spends."""
        out: list[int] = []
        at = data.find(needle)
        most = Places.MOST if budget is None else min(Places.MOST, budget[0])
        while at >= 0:
            if len(out) >= most:
                raise Places.too_many()
            out.append(at)
            at = data.find(needle, at + 1)
        if budget is not None:
            budget[0] -= len(out)
        return out

    @staticmethod
    def budget(seen: dict[Any, Any]) -> list[int]:
        """What one file may still hold of anchor occurrences and places to try, across every
        string searched in it (`Places.MOST` in all): the bound is the whole match's, not each
        string's."""
        held: list[int] = seen.setdefault(("budget",), [Places.MOST])
        return held

    @staticmethod
    def too_many() -> Unbounded:
        return Unbounded(f"more than {Places.MOST:,} places to try in one file")


__all__ = ["Places", "Unbounded"]
