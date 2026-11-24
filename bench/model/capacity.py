"""Model capacity chosen by family-grouped cross-validation, and recorded with the model.

`Capacity.select` scores every point of a grid (tree count, leaves per tree, learning rate, minimum leaf size) on folds in
which no malware family is in more than one fold, takes the point with the best mean score (the smaller model on a tie),
and returns the record: the grid, the whole curve (every point's score on every fold) and the chosen values.
`Capacity.attach` puts that record in the exported model, so the model says how its capacity was set.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, ClassVar


class Capacity:
    GRID: ClassVar[dict[str, tuple[float, ...]]] = {
        "trees": (100, 300, 600),
        "leaves": (15, 31, 63),
        "learning_rate": (0.04, 0.08),
        "min_leaf": (10, 20, 50),
    }
    FOLDS: ClassVar[int] = 5

    @classmethod
    def fold_of(cls, family: str, folds: int | None = None) -> int:
        """The fold a family belongs to: fixed by its name, so every unit of a family is in the same fold."""
        return int(hashlib.sha256(family.encode()).hexdigest(), 16) % (folds or cls.FOLDS)

    @classmethod
    def points(cls, grid: Mapping[str, Sequence[float]] | None = None) -> list[dict[str, float]]:
        grid = grid or cls.GRID
        names = list(grid)
        return [
            dict(zip(names, values, strict=True))
            for values in itertools.product(*(grid[n] for n in names))
        ]

    @classmethod
    def select(
        cls,
        families: Iterable[str],
        score: Callable[[dict[str, float], set[str], set[str]], float],
        grid: Mapping[str, Sequence[float]] | None = None,
        folds: int | None = None,
    ) -> dict[str, Any]:
        """The record of a search: `score(point, fit_families, held_families)` is the held-out score of a model of `point`."""
        count = folds or cls.FOLDS
        unique = sorted(set(families))
        held = [{f for f in unique if cls.fold_of(f, count) == k} for k in range(count)]
        usable = [k for k in range(count) if held[k] and len(held[k]) < len(unique)]
        if not usable:
            raise ValueError("the families cannot be split into folds of their own")
        curve = []
        for point in cls.points(grid):
            scores = [score(point, set(unique) - held[k], held[k]) for k in usable]
            curve.append({"point": point, "folds": scores, "mean": sum(scores) / len(scores)})
        best = max(
            curve,
            key=lambda c: (c["mean"], -c["point"].get("trees", 0), -c["point"].get("leaves", 0)),
        )
        return {
            "method": "family-grouped cross-validation",
            "folds": len(usable),
            "grid": {name: list(values) for name, values in (grid or cls.GRID).items()},
            "curve": curve,
            "chosen": dict(best["point"]),
        }

    @staticmethod
    def attach(exported: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        """`exported` with the search record under `capacity`."""
        return {**exported, "capacity": record}


__all__ = ["Capacity"]
