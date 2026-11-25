"""One decision line per area, set on the legitimate work set and recorded with its upper bound.

The line of an area is the lowest score at which the share of that area's legitimate work-set packages scoring at or above it,
at the upper end of the 95% Wilson interval, is within the budget (0.5% by default). `AreaLines.enforce` raises a line that
would break the budget to the lowest one that holds it and returns, for every area, the line, the legitimate packages it blocks,
how many there are and the upper bound, so the model says what each line was held to.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from bench.cdi.gate import Gate


class AreaLines:
    BUDGET: ClassVar[float] = 0.005
    NEVER: ClassVar[float] = 1.01
    """A line above every score: it blocks nothing."""

    @classmethod
    def upper(cls, scores: Sequence[float], line: float) -> tuple[int, float]:
        blocked = sum(1 for s in scores if s >= line)
        return blocked, Gate.wilson(blocked, len(scores))[1]

    @classmethod
    def lowest(cls, scores: Sequence[float], budget: float | None = None) -> float:
        """The lowest line whose upper bound is within `budget`; `NEVER` when even blocking one package breaks it."""
        budget = cls.BUDGET if budget is None else budget
        for line in sorted(set(scores), reverse=False):
            if cls.upper(scores, line)[1] <= budget:
                return float(line)
        return cls.NEVER

    @classmethod
    def enforce(
        cls,
        lines: Mapping[str, float],
        legit_scores: Mapping[str, Sequence[float]],
        budget: float | None = None,
    ) -> tuple[dict[str, float], dict[str, dict[str, Any]]]:
        """`(lines, record)`: each area's line, raised only as far as the budget needs, and what it was held to."""
        budget = cls.BUDGET if budget is None else budget
        out: dict[str, float] = {}
        record: dict[str, dict[str, Any]] = {}
        for area, line in lines.items():
            scores = list(legit_scores.get(area, ()))
            if scores and cls.upper(scores, line)[1] > budget:
                line = max(line, cls.lowest(scores, budget))
            blocked, upper = cls.upper(scores, line) if scores else (0, 1.0)
            out[area] = line
            record[area] = {
                "line": line,
                "legit_blocked": blocked,
                "legit_n": len(scores),
                "upper": round(upper, 6),
                "budget": budget,
            }
        return out, record


__all__ = ["AreaLines"]
