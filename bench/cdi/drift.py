"""The drift watch: the share of packages near a model's decision line, for each area, window by window.

A model that ages shows it before its numbers fall: more and more packages score close to the line it blocks at, because what
it was taught no longer separates what arrives. For each area and each window this records the share of scored packages whose
score lies within `margin` of the line, with its 95% interval, and compares it with the share when the model was accepted:

    ok       the interval of the latest share still holds the accepted share
    drift    the latest share's lower bound is above the accepted share (more packages near the line than at acceptance)

The series is plain data, one point per window per area, in window order; a window not after the last is refused. It holds counts and
shares, never a package."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

from bench.cdi.gate import Gate

DEFAULT_MARGIN: Final = 0.05
MIN_SCORED: Final = 200


class DriftRefused(ValueError):
    """A window is out of order or a score or line is not usable."""


class DriftSeries:
    def __init__(self, line: float, margin: float = DEFAULT_MARGIN, accepted: Mapping[str, float] | None = None) -> None:
        if not 0.0 < margin < 1.0:
            raise DriftRefused("the margin is between 0 and 1")
        self.line, self.margin = line, margin
        #: The near-line share of each area when the model was accepted.
        self.accepted: dict[str, float] = dict(accepted or {})
        self.points: dict[str, list[dict[str, Any]]] = {}
        self.last_window = ""

    def near(self, scores: Iterable[float]) -> tuple[int, int]:
        values = list(scores)
        if any(not 0.0 <= s <= 1.0 for s in values):
            raise DriftRefused("a score is between 0 and 1")
        return sum(1 for s in values if abs(s - self.line) <= self.margin), len(values)

    def accept(self, area: str, scores: Iterable[float]) -> float:
        """Records the share near the line at the time the model was accepted: what later windows are compared with."""
        k, n = self.near(scores)
        if n < MIN_SCORED:
            raise DriftRefused(f"area {area}: fewer than {MIN_SCORED} scored packages at acceptance")
        self.accepted[area] = k / n
        return self.accepted[area]

    def add(self, window: str, scores_by_area: Mapping[str, Iterable[float]]) -> list[dict[str, Any]]:
        """One point for each area of the window. Windows are given in order; a window not after the last is refused."""
        if window <= self.last_window:
            raise DriftRefused("a window is added once, after the last one")
        added = []
        for area in sorted(scores_by_area):
            k, n = self.near(scores_by_area[area])
            low, high = Gate.wilson(k, n)
            base = self.accepted.get(area)
            state = "unmeasured" if n < MIN_SCORED or base is None else ("drift" if low > base else "ok")
            point = {"window": window, "area": area, "near": k, "scored": n, "share": k / n if n else None,
                     "low": low, "high": high, "accepted_share": base, "state": state}
            self.points.setdefault(area, []).append(point)
            added.append(point)
        self.last_window = window
        return added

    def drifting(self) -> list[str]:
        """The areas whose latest point says drift."""
        return sorted(a for a, pts in self.points.items() if pts and pts[-1]["state"] == "drift")
