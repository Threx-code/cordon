"""The LightGBM path of `bench/model/verdict_train.py`: its trees exported as `VerdictModel.score`
walks them, and the line placed by malware recall instead of a benign budget."""

from __future__ import annotations

import sys

import pytest

from cordon_scanner.decide.verdict import VerdictModel
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from verdict_train import VerdictTrain


class LightGbmKit:
    """A booster stand-in: `dump_model()` in LightGBM's own shape, two trees over three columns."""

    class Booster:
        @staticmethod
        def dump_model() -> dict:
            leaf = lambda v: {"leaf_index": 0, "leaf_value": v}  # noqa: E731
            return {
                "tree_info": [
                    {
                        "tree_structure": {
                            "split_feature": 2,
                            "threshold": 0.5,
                            "decision_type": "<=",
                            "default_left": True,
                            "left_child": leaf(-1.0),
                            "right_child": {
                                "split_feature": 0,
                                "threshold": 3.0,
                                "decision_type": "<=",
                                "default_left": False,
                                "left_child": leaf(0.5),
                                "right_child": leaf(2.0),
                            },
                        }
                    },
                    {"tree_structure": leaf(0.25)},
                ]
            }

    class Classifier:
        booster_ = None

    @classmethod
    def model(cls) -> dict:
        clf = cls.Classifier()
        clf.booster_ = cls.Booster()
        return VerdictTrain.export(clf, ["pkg:a", "pkg:unused", "r:R.1"])


class TestTheExport:
    def test_it_names_only_the_features_a_split_reads(self) -> None:
        assert LightGbmKit.model()["features"] == ["r:R.1", "pkg:a"]

    @pytest.mark.parametrize(
        ("features", "raw"),
        [
            ({}, -1.0 + 0.25),
            ({"r:R.1": 1.0}, 0.5 + 0.25),
            ({"r:R.1": 1.0, "pkg:a": 7.0}, 2.0 + 0.25),
            ({"pkg:unused": 9.0}, -1.0 + 0.25),
        ],
        ids=["nothing", "rule-only", "rule-and-feature", "an-unread-feature"],
    )
    def test_it_scores_as_the_trees_say(self, features: dict, raw: float) -> None:
        import math

        assert VerdictModel.score(LightGbmKit.model(), features) == pytest.approx(
            1 / (1 + math.exp(-raw)), abs=1e-6
        )

    def test_a_split_it_cannot_walk_is_refused(self) -> None:
        clf = LightGbmKit.Classifier()

        class Odd:
            @staticmethod
            def dump_model() -> dict:
                return {
                    "tree_info": [
                        {
                            "tree_structure": {
                                "split_feature": 0,
                                "threshold": "1||2",
                                "decision_type": "==",
                                "left_child": {"leaf_value": 0.0},
                                "right_child": {"leaf_value": 1.0},
                            }
                        }
                    ]
                }

        clf.booster_ = Odd()
        with pytest.raises(SystemExit):
            VerdictTrain.export(clf, ["pkg:a"])


class TestTheRecallLine:
    @staticmethod
    def line(scores: list[float], recall: float, reach_all: bool = True) -> float:
        malware = [{"score": s, "has_code": reach_all or i % 2 == 0} for i, s in enumerate(scores)]
        grid = sorted({*scores, 1.01})
        return VerdictTrain.recall_line(
            malware, grid, lambda r, t: r["has_code"] and r["score"] >= t, recall
        )

    def test_the_highest_line_that_still_blocks_the_share(self) -> None:
        scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
        assert self.line(scores, 0.8) == 0.3
        assert self.line(scores, 1.0) == 0.1

    def test_the_share_is_of_what_the_line_can_reach(self) -> None:
        # Half the malware carries no code: no line reaches it, so the line is placed on the half it
        # can, not driven to the bottom of the grid chasing the rest.
        scores = [0.9, 0.1, 0.8, 0.1, 0.7, 0.1, 0.6, 0.1]
        assert self.line(scores, 1.0, reach_all=False) == 0.6

    def test_no_malware_blocks_nothing(self) -> None:
        assert VerdictTrain.recall_line([], [0.1, 1.01], lambda r, t: True, 0.98) == 1.01
