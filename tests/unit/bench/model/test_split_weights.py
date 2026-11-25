"""SI-T20: a family never appears in two splits, the weight of hard legitimate units is recorded, and the time-split recall is reported."""

from __future__ import annotations

from typing import Any

import pytest
from bench.model.split_weights import SplitWeights
from bench.model.verdict_train import VerdictTrain


class Rows:
    @staticmethod
    def of_families(families: int, releases: int) -> list[dict[str, Any]]:
        """Fixture rows the way the trainer makes them: every release of a family gets the half of the family's name."""
        return [
            {
                "family": f"family-{n}",
                "family_half": VerdictTrain.half(f"family-{n}"),
                "label": 1,
                "date": f"2026-0{1 + release % 9}-15",
            }
            for n in range(families)
            for release in range(releases)
        ]


class TestAFamilyIsOnOneSide:
    def test_the_trainers_half_of_a_family_is_the_same_for_every_release(self) -> None:
        rows = Rows.of_families(60, 5)
        assert SplitWeights.one_side(rows) == 60

    def test_both_halves_are_used(self) -> None:
        halves = {VerdictTrain.half(f"family-{n}") for n in range(60)}
        assert halves == {"work", "holdout"}

    def test_a_family_with_a_unit_on_each_half_is_refused_with_a_count(self) -> None:
        rows = Rows.of_families(3, 2)
        rows[0]["family_half"] = "holdout" if rows[1]["family_half"] == "work" else "work"
        with pytest.raises(ValueError, match="1 family has units on both halves"):
            SplitWeights.one_side(rows)

    def test_the_message_never_names_a_family(self) -> None:
        rows = Rows.of_families(3, 2)
        rows[0]["family_half"] = "x" + rows[0]["family_half"]
        with pytest.raises(ValueError) as caught:
            SplitWeights.one_side(rows)
        assert "family-" not in str(caught.value)


class TestHardLegitimateUnitsAreWeightedAndTheWeightIsRecorded:
    ROWS: list[dict[str, Any]] = [  # noqa: RUF012
        {"label": 0, "family": "a"},
        {"label": 0, "family": "b"},
        {"label": 0, "family": "c"},
        {"label": 1, "family": "d"},
        {"label": 1, "family": "e"},
    ]
    SCORES = (0.1, 0.5, 0.9, 0.9, 0.2)

    def test_only_a_legitimate_unit_at_or_over_the_score_is_weighted(self) -> None:
        weights, _ = SplitWeights.hard_legit(self.ROWS, self.SCORES, factor=3.0, from_score=0.5)
        assert weights == [1.0, 3.0, 3.0, 1.0, 1.0]

    def test_the_record_holds_the_rule_the_numbers_and_the_sum(self) -> None:
        _, record = SplitWeights.hard_legit(self.ROWS, self.SCORES, factor=3.0, from_score=0.5)
        assert record["factor"] == 3.0 and record["from_score"] == 0.5
        assert record["legitimate_units"] == 3 and record["hard_units"] == 2
        assert record["weight_sum"] == 1.0 + 3.0 + 3.0 + 1.0 + 1.0
        assert "out-of-fold" in record["scores"] and record["rule"]

    def test_the_default_score_is_a_half(self) -> None:
        weights, record = SplitWeights.hard_legit(self.ROWS, self.SCORES, factor=2.0)
        assert record["from_score"] == 0.5 and weights.count(2.0) == 2

    @pytest.mark.parametrize("factor", [1.0, 0.5, 0, -2])
    def test_a_factor_that_does_not_raise_the_weight_is_refused(self, factor: float) -> None:
        with pytest.raises(ValueError, match="above 1"):
            SplitWeights.hard_legit(self.ROWS, self.SCORES, factor=factor)

    def test_a_score_missing_for_a_row_is_refused(self) -> None:
        with pytest.raises(ValueError, match="one score"):
            SplitWeights.hard_legit(self.ROWS, self.SCORES[:-1], factor=2.0)

    def test_the_record_rides_with_the_exported_model(self) -> None:
        _, record = SplitWeights.hard_legit(self.ROWS, self.SCORES, factor=3.0)
        exported = SplitWeights.attach({"trees": []}, hard_legit=record)
        assert exported["hard_legit"] == record and exported["trees"] == []


class TestTheTimeSplitRecallIsReported:
    ROWS: list[dict[str, Any]] = [  # noqa: RUF012
        {"label": 1, "date": "2026-01-10"},
        {"label": 1, "date": "2026-03-01"},
        {"label": 1, "date": "2026-03-02"},
        {"label": 1, "date": "2026-04-01"},
        {"label": 0, "date": "2026-04-01"},
        {"label": 1, "date": ""},
    ]

    def test_recall_is_over_the_malicious_units_on_or_after_the_cut_off(self) -> None:
        flagged = [True, False, True, False, True, True]
        report = SplitWeights.time_check(self.ROWS, flagged, "2026-03-01")
        assert report["malicious_before"] == 1 and report["malicious_after"] == 3
        assert report["caught_after"] == 1 and report["recall_after"] == round(1 / 3, 6)

    def test_a_unit_with_no_date_and_a_legitimate_unit_are_not_counted(self) -> None:
        report = SplitWeights.time_check(self.ROWS, [True] * 6, "2026-01-01")
        assert report["malicious_after"] == 4 and report["recall_after"] == 1.0

    def test_with_nothing_after_the_cut_off_no_recall_is_reported_and_it_says_so(self) -> None:
        report = SplitWeights.time_check(self.ROWS, [True] * 6, "2027-01-01")
        assert report["recall_after"] is None and "no recall" in report["note"]

    def test_one_flag_for_each_row(self) -> None:
        with pytest.raises(ValueError, match="one flag"):
            SplitWeights.time_check(self.ROWS, [True], "2026-03-01")
