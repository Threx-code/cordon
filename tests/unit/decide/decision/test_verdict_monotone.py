"""The shipped verdict trees never lower the score for a stronger or an extra finding; the package facts that name a reached capability are the part still to be made so.

A tree sum is monotone in a feature when, at every split on it, every leaf on the higher side is at least as large as every leaf on the lower side. This reads that off the shipped model file. The
finding features (a rule that fired, a family of rules, a category, a gate, a weight of code or manifest findings) hold it today. The package facts of reached capabilities (install hooks, imports at load
time, what an agent can reach) are free in the trees, and the test that they be monotone is written and expected to fail until the model is refitted with that constraint.
"""

from __future__ import annotations

import gzip
import json
from typing import Any, ClassVar

import pytest

from cordon_scanner.decide import verdict


class Trees:
    FINDING: ClassVar[tuple[str, ...]] = ("r:", "fam:", "cat:", "w:", "gate", "max")
    REACHED: ClassVar[tuple[str, ...]] = ("pkg:install", "pkg:import", "pkg:agent_can")

    @staticmethod
    def model() -> dict[str, Any]:
        return json.loads(gzip.decompress(verdict.MODEL_PATH.read_bytes()))

    @staticmethod
    def leaves(tree: list[dict[str, Any]], node: int) -> list[float]:
        found: list[float] = []
        stack = [node]
        while stack:
            current = tree[stack.pop()]
            if current["leaf"]:
                found.append(current["value"])
            else:
                stack += [current["left"], current["right"]]
        return found

    @classmethod
    def broken(cls, model: dict[str, Any], prefixes: tuple[str, ...]) -> tuple[int, int]:
        """(splits on a feature that starts with one of `prefixes`, those whose higher side has a leaf below a leaf of the lower side)."""
        names = model["features"]
        splits = breaks = 0
        for tree in model["trees"]:
            for node in tree:
                if node["leaf"] or not names[node["feature"]].startswith(prefixes):
                    continue
                splits += 1
                if min(cls.leaves(tree, node["right"])) < max(cls.leaves(tree, node["left"])):
                    breaks += 1
        return splits, breaks


class TestTheShippedTrees:
    def test_a_finding_never_lowers_the_score(self) -> None:
        splits, breaks = Trees.broken(Trees.model(), Trees.FINDING)
        assert splits > 0 and breaks == 0

    @pytest.mark.xfail(
        strict=True,
        reason="the package facts of reached capabilities are not yet constrained in the trees; the next refit adds the constraint",
    )
    def test_a_reached_capability_never_lowers_the_score(self) -> None:
        splits, breaks = Trees.broken(Trees.model(), Trees.REACHED)
        assert splits > 0 and breaks == 0

    def test_the_check_finds_a_split_that_lowers_the_score(self) -> None:
        model = {
            "features": ["r:X"],
            "trees": [
                [
                    {"leaf": False, "feature": 0, "left": 1, "right": 2},
                    {"leaf": True, "value": 1.0},
                    {"leaf": True, "value": 0.5},
                ]
            ],
        }
        assert Trees.broken(model, ("r:",)) == (1, 1)

    def test_the_check_passes_a_split_that_raises_it(self) -> None:
        model = {
            "features": ["r:X"],
            "trees": [
                [
                    {"leaf": False, "feature": 0, "left": 1, "right": 2},
                    {"leaf": True, "value": 0.5},
                    {"leaf": True, "value": 1.0},
                ]
            ],
        }
        assert Trees.broken(model, ("r:",)) == (1, 0)
