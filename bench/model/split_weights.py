"""Training-data discipline for the verdict model (SI-T20): families on one side, hard legitimate units weighted and the weight recorded, a time check.

* `SplitWeights.one_side` refuses rows in which a family has a unit on each half of the split (every release of a family is on one side).
* `SplitWeights.hard_legit` gives a legitimate unit whose out-of-fold score (the score of a model that never saw its family) is at least `from_score`
  the weight `factor`, every other unit weight 1, and returns the record of what was done: the rule, the numbers and the sum, which the trainer's
  report carries (never the model: that is trees and feature names only).
* `SplitWeights.time_check` reports, for the malicious units dated on or after a cut-off, how many the model blocks, as counts and a recall; with
  no unit after the cut-off it says so rather than reporting a number.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any, ClassVar


class SplitWeights:
    DEFAULT_FROM: ClassVar[float] = 0.5

    @staticmethod
    def families_split(rows: Sequence[Mapping[str, Any]], side: str = "family_half") -> int:
        """How many families have rows on more than one value of `side` (the half each row was given): a count, never names."""
        sides: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            sides[str(row["family"])].add(str(row[side]))
        return sum(1 for values in sides.values() if len(values) > 1)

    @classmethod
    def one_side(cls, rows: Sequence[Mapping[str, Any]], side: str = "family_half") -> int:
        """The number of families checked; `ValueError` (with the count of families split, never their names) when a family has rows on two sides."""
        split = cls.families_split(rows, side)
        if split:
            raise ValueError(
                f"{split} famil{'y has' if split == 1 else 'ies have'} units on both halves of the split"
            )
        return len({str(row["family"]) for row in rows})

    @staticmethod
    def day(text: str) -> str:
        """A day as `YYYY-MM-DD`, or `ValueError`: a string compare of any other form would sort wrongly and report no recall silently."""
        if len(text) != 10:
            raise ValueError(f"a day is YYYY-MM-DD, not {text!r}")
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError:
            raise ValueError(f"a day is YYYY-MM-DD, not {text!r}") from None

    @classmethod
    def hard_legit(
        cls,
        rows: Sequence[Mapping[str, Any]],
        scores: Sequence[float],
        *,
        factor: float,
        from_score: float | None = None,
    ) -> tuple[list[float], dict[str, Any]]:
        """`(weights, record)`: one weight per row; `scores` are out-of-fold. A row is hard when it is legitimate (`label` 0) and its score is
        at least `from_score` (0.5 when none is given). `factor` is above 1."""
        if len(scores) != len(rows):
            raise ValueError("one score for each row")
        if any(math.isnan(score) for score in scores):
            raise ValueError("a score is not a number")
        if not factor > 1:
            raise ValueError("the weight of a hard legitimate unit is above 1")
        floor = cls.DEFAULT_FROM if from_score is None else from_score
        weights = [
            float(factor) if (not row["label"] and score >= floor) else 1.0
            for row, score in zip(rows, scores, strict=True)
        ]
        legit = sum(1 for row in rows if not row["label"])
        hard = sum(1 for w in weights if w != 1.0)
        record = {
            "rule": "a legitimate unit whose out-of-fold score is at least from_score is weighted by factor; every other unit by 1",
            "from_score": floor,
            "factor": float(factor),
            "legitimate_units": legit,
            "hard_units": hard,
            "weight_sum": round(sum(weights), 6),
            "scores": "out-of-fold, family-grouped",
        }
        return weights, record

    @staticmethod
    def time_check(
        rows: Sequence[Mapping[str, Any]], flagged: Sequence[bool], cutoff: str
    ) -> dict[str, Any]:
        """The malicious units dated `cutoff` or later (`date` as YYYY-MM-DD; a unit with no date is not counted) and how many of them are flagged."""
        if len(flagged) != len(rows):
            raise ValueError("one flag for each row")
        before = after = caught = 0
        for row, hit in zip(rows, flagged, strict=True):
            date = str(row.get("date") or "")
            if not row["label"] or not date:
                continue
            if date >= cutoff:
                after += 1
                caught += 1 if hit else 0
            else:
                before += 1
        return {
            "cutoff": cutoff,
            "malicious_before": before,
            "malicious_after": after,
            "caught_after": caught,
            "recall_after": round(caught / after, 6) if after else None,
            "note": ""
            if after
            else "no malicious unit is dated on or after the cut-off: no recall is reported",
        }


__all__ = ["SplitWeights"]
