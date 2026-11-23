"""Capacity is chosen on folds that never split a family, and the model records the grid, the curve and the choice."""

from __future__ import annotations

import json

import pytest
from bench.model.capacity import Capacity

FAMILIES = [f"family-{n}" for n in range(40)]


class Scorers:
    @staticmethod
    def prefers_300_trees_and_31_leaves(
        point: dict[str, float], fit: set[str], held: set[str]
    ) -> float:
        return (
            -abs(point["trees"] - 300) / 1000
            - abs(point["leaves"] - 31) / 100
            - point["min_leaf"] / 10000
        )


class TestFamilyGroupedFolds:
    def test_every_family_is_in_one_fold(self) -> None:
        folds = {f: Capacity.fold_of(f) for f in FAMILIES}
        assert set(folds.values()) == set(range(Capacity.FOLDS))

    def test_a_search_never_fits_on_a_family_it_is_scored_on(self) -> None:
        seen: list[tuple[set[str], set[str]]] = []

        def score(point: dict[str, float], fit: set[str], held: set[str]) -> float:
            seen.append((fit, held))
            return 0.0

        Capacity.select(FAMILIES, score)
        assert seen and all(not (fit & held) and fit | held == set(FAMILIES) for fit, held in seen)

    def test_one_family_cannot_be_split(self) -> None:
        with pytest.raises(ValueError, match="folds of their own"):
            Capacity.select(["only"], lambda *_: 0.0)


class TestTheRecord:
    def test_the_chosen_point_is_the_best_mean_of_the_curve(self) -> None:
        record = Capacity.select(FAMILIES, Scorers.prefers_300_trees_and_31_leaves)
        assert (record["chosen"]["trees"], record["chosen"]["leaves"]) == (300, 31) and record[
            "chosen"
        ]["min_leaf"] == 10

    def test_the_curve_has_every_point_of_the_grid_with_every_fold(self) -> None:
        record = Capacity.select(FAMILIES, Scorers.prefers_300_trees_and_31_leaves)
        assert len(record["curve"]) == 3 * 3 * 2 * 3 and all(
            len(c["folds"]) == record["folds"] for c in record["curve"]
        )
        assert set(record["grid"]) == {"trees", "leaves", "learning_rate", "min_leaf"}

    def test_a_tie_takes_the_smaller_model(self) -> None:
        record = Capacity.select(FAMILIES, lambda *_: 0.5)
        assert (record["chosen"]["trees"], record["chosen"]["leaves"]) == (100, 15)

    def test_the_exported_model_carries_the_grid_the_curve_and_the_choice(self) -> None:
        record = Capacity.select(FAMILIES, Scorers.prefers_300_trees_and_31_leaves)
        model = json.loads(json.dumps(Capacity.attach({"features": ["a"], "trees": []}, record)))
        assert {"grid", "curve", "chosen"} <= set(model["capacity"]) and model["features"] == ["a"]
