"""A scheduled retrain gives a model, its report and a shadow run, and the drift series exists."""

from __future__ import annotations

import sys

import pytest
from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.drift import DriftSeries
from bench.cdi.retrain import Cadence, Retrain, RetrainRefused, TrainingList
from bench.model import area

DAY = 86_400.0
DIGEST = "ab" * 32
GOOD = {
    "work": {"malware_lost": 0},
    "areas": {"npm": {"legit_blocked": 2, "legit_n": 9000}},
    "levers": {"model": {"malware_blocked": 410}, "rules": {"malware_blocked": 380}},
    "ablation": {"imports": {"extra_legit_blocks": 1, "extra_malware_caught": 12}},
    "detector_only": {"malware_blocked": 30, "legit_blocked": 1},
    "trained_features": DIGEST,
    "scored_features": DIGEST,
    "heldout_uses": {"npm-held": 1},
}


class Helpers:
    @staticmethod
    def scores(near: int, far: int) -> list[float]:
        return [0.91] * near + [0.1] * far

    @staticmethod
    def drift() -> DriftSeries:
        s = DriftSeries(0.9)
        s.accept("npm", Helpers.scores(20, 980))
        return s

    @staticmethod
    def run(fakes: Fakes, evidence, ids=("a", "b", "c"), shadow=None, series=None, window="w1"):
        return Retrain.run(
            reason="cadence",
            training=TrainingList.build(ids, []),
            train=fakes.train,
            evidence=evidence,
            shadow=shadow or Fakes.shadow,
            drift=series or Helpers.drift(),
            window=window,
            scores_by_area={"npm": Helpers.scores(20, 980)},
        )




class Fakes:
    ran: list[list[str]]

    def __init__(self) -> None:
        self.ran = []
        self.tmp = None

    def train(self, ids: list[str]) -> dict:
        self.ran.append(ids)
        return {"model": "model-2026-w47", "training_list_sha": area.Contract.training_list_sha(ids)}

    @staticmethod
    def passing(model) -> dict:
        return GOOD

    @staticmethod
    def failing(model) -> dict:
        return {**GOOD, "work": {"malware_lost": 2}}

    @staticmethod
    def shadow(model) -> dict:
        return {"model": model["model"], "enforcement": "shadow"}






class TestAScheduledRetrainLeavesAModelItsReportAndAShadowRun:
    def test_a_passing_retrain_gives_the_model_the_report_the_shadow_run_and_a_drift_point(self) -> None:
        fakes = Fakes()
        out = Helpers.run(fakes, Fakes.passing)
        assert out["model"]["model"] == "model-2026-w47" and out["model"]["training_list_sha"].startswith("sha256:")
        assert out["report"]["accepted"] is True and out["shadow"] == {"model": "model-2026-w47", "enforcement": "shadow"}
        assert out["outcome"] == "shadow" and out["drift"][0]["area"] == "npm" and out["drift"][0]["state"] == "ok"

    def test_a_retrain_that_fails_the_acceptance_is_not_put_into_shadow(self) -> None:
        out = Helpers.run(Fakes(), Fakes.failing)
        assert out["report"]["failed"] == ["lose_zero"] and out["shadow"] is None and out["outcome"] == "research"

    def test_the_drift_series_gains_a_point_each_run_even_when_the_model_is_refused(self) -> None:
        series = Helpers.drift()
        Helpers.run(Fakes(), Fakes.failing, series=series, window="w1")
        Helpers.run(Fakes(), Fakes.passing, series=series, window="w2")
        assert [p["window"] for p in series.points["npm"]] == ["w1", "w2"]

    def test_a_model_that_starts_by_blocking_is_refused(self) -> None:
        with pytest.raises(RetrainRefused, match="starts in shadow"):
            Helpers.run(Fakes(), Fakes.passing, shadow=lambda m: {"enforcement": "block"})

    def test_a_trainer_that_gave_no_list_hash_did_not_run_through_the_entry_point(self) -> None:
        with pytest.raises(RetrainRefused, match="entry point"):
            Retrain.run(
                reason="cadence",
                training=TrainingList.build(["a"], []),
                train=lambda ids: {"model": "m"},
                evidence=Fakes.passing,
                shadow=Fakes.shadow,
                drift=Helpers.drift(),
                window="w1",
                scores_by_area={"npm": Helpers.scores(20, 980)},
            )


class TestWhenAndWhatItTrainsOn:
    def test_it_runs_on_a_new_labelled_batch_at_once_and_on_the_cadence_otherwise(self) -> None:
        assert Cadence.due(10 * DAY, 9 * DAY, 7 * DAY, new_batch=True) == "batch"
        assert Cadence.due(10 * DAY, 2 * DAY, 7 * DAY, new_batch=False) == "cadence"
        assert Cadence.due(10 * DAY, 9 * DAY, 7 * DAY, new_batch=False) is None
        assert Cadence.due(10 * DAY, None, 7 * DAY, new_batch=False) == "cadence"

    def test_a_live_capture_joins_training_only_with_two_distinct_reviewers(self) -> None:
        captures = [
            {"id": "c1", "reviewers": ["r1", "r2"]},
            {"id": "c2", "reviewers": ["r1"]},
            {"id": "c3", "reviewers": ["r1", "r1"]},
        ]
        built = TrainingList.build(["s1", "s2"], captures)
        assert built["ids"] == ["c1", "s1", "s2"] and (built["captures_joined"], built["captures_left_out"]) == (1, 2)

    def test_a_capture_that_is_held_out_is_refused_whole(self) -> None:
        with pytest.raises(RetrainRefused, match="held out"):
            TrainingList.build(["s1"], [{"id": "h1", "reviewers": ["r1", "r2"]}], held_out=frozenset({"h1"}))

    def test_a_standing_list_holding_a_held_out_unit_is_refused(self) -> None:
        with pytest.raises(RetrainRefused, match="standing list"):
            TrainingList.build(["h1"], [], held_out=frozenset({"h1"}))

    def test_the_trainer_is_given_the_sorted_list_with_the_joined_captures(self) -> None:
        fakes = Fakes()
        Retrain.run(
            reason="batch",
            training=TrainingList.build(["b", "a"], [{"id": "c", "reviewers": ["x", "y"]}]),
            train=fakes.train,
            evidence=Fakes.passing,
            shadow=Fakes.shadow,
            drift=Helpers.drift(),
            window="w1",
            scores_by_area={"npm": Helpers.scores(20, 980)},
        )
        assert fakes.ran == [["a", "b", "c"]]
