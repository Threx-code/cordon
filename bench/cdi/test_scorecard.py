"""SI-L10, SI-L11: the scorecard against a frozen baseline, and the drill for each case that does not settle a candidate."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from bench.cdi.scorecard import Baseline, BaselineEdited, Conclusion, Proportions, Scorecard

BASE = Baseline.freeze({"mal_blocked": 300, "mal_n": 400, "benign_blocked": 5, "benign_n": 5_000})


class Kit:
    @staticmethod
    def candidate(mal_blocked: int = 360, mal_n: int = 400, benign_blocked: int = 5, benign_n: int = 5_000) -> dict[str, int]:
        return {"mal_blocked": mal_blocked, "mal_n": mal_n, "benign_blocked": benign_blocked, "benign_n": benign_n}

    @staticmethod
    def card(**over: int) -> dict[str, Any]:
        return Scorecard.of(BASE, Kit.candidate(**over))


class TestTheScorecard:
    def test_the_gain_is_shown_over_the_baseline_with_its_bounds(self) -> None:
        card = Scorecard.of(BASE, Kit.candidate())
        assert card["recall_baseline"] == 0.75 and card["recall_candidate"] == 0.9
        assert card["recall_gain"] == pytest.approx(0.15)
        assert 0 < card["recall_gain_low"] < card["recall_gain"] < card["recall_gain_high"]
        assert card["incremental"] is True and card["baseline_digest"] == BASE["digest"]

    def test_the_same_numbers_as_the_baseline_are_not_an_incremental_value(self) -> None:
        card = Scorecard.of(BASE, Kit.candidate(mal_blocked=300))
        assert card["recall_gain"] == 0 and card["incremental"] is False

    def test_a_small_gain_whose_bound_spans_zero_is_not_incremental(self) -> None:
        card = Scorecard.of(BASE, Kit.candidate(mal_blocked=305))
        assert card["recall_gain_low"] < 0 < card["recall_gain_high"] and card["incremental"] is False

    def test_the_benign_block_rate_has_an_upper_bound(self) -> None:
        card = Scorecard.of(BASE, Kit.candidate(benign_blocked=10))
        assert card["benign_block_rate"] == 0.002 and card["benign_block_upper"] > 0.002

    def test_more_blocked_than_units_is_refused(self) -> None:
        with pytest.raises(ValueError, match="mal_blocked 401 is not within mal_n 400"):
            Scorecard.of(BASE, Kit.candidate(mal_blocked=401))
        with pytest.raises(ValueError, match="benign_blocked"):
            Scorecard.of(BASE, Kit.candidate(benign_blocked=-1))

    def test_an_edited_baseline_is_refused(self) -> None:
        edited = copy.deepcopy(BASE)
        edited["counts"]["mal_blocked"] = 100
        with pytest.raises(BaselineEdited):
            Scorecard.of(edited, Kit.candidate())

    def test_a_baseline_with_a_changed_digest_is_refused(self) -> None:
        with pytest.raises(BaselineEdited):
            Scorecard.of({**BASE, "digest": "0" * 64}, Kit.candidate())

    def test_the_difference_of_equal_proportions_is_centred_on_zero(self) -> None:
        delta, low, high = Proportions.difference(50, 100, 50, 100)
        assert delta == 0 and low < 0 < high and low == pytest.approx(-high)

    def test_an_empty_set_gives_the_widest_interval(self) -> None:
        assert Proportions.difference(0, 0, 5, 10) == (0.0, -1.0, 1.0)


class TestEveryCaseEndsInResearchOrShadow:
    """SI-L11: one drill per case; none ends in success."""

    def test_unavailable_data_ends_in_research(self) -> None:
        result = Conclusion.of({"pypi": Kit.card(), "npm": None})
        assert result["outcome"] == "research" and "data unavailable for npm" in result["reasons"][0]

    def test_no_areas_at_all_ends_in_research(self) -> None:
        assert Conclusion.of({})["outcome"] == "research"

    def test_a_small_n_ends_in_research(self) -> None:
        result = Conclusion.of({"pypi": Kit.card(mal_blocked=100, mal_n=120)})
        assert result["outcome"] == "research" and "small n in pypi" in result["reasons"][0]

    def test_too_few_benign_units_is_a_small_n(self) -> None:
        assert Conclusion.of({"pypi": Kit.card(benign_n=2_999)})["outcome"] == "research"

    def test_an_inconclusive_gain_ends_in_research(self) -> None:
        result = Conclusion.of({"pypi": Kit.card(mal_blocked=305), "npm": Kit.card(mal_blocked=303)})
        assert result["outcome"] == "research" and "spans zero" in result["reasons"][0]

    def test_a_gain_in_one_area_only_is_not_generalisable_and_ends_in_shadow(self) -> None:
        result = Conclusion.of({"pypi": Kit.card(), "npm": Kit.card(mal_blocked=300)})
        assert result["outcome"] == "shadow" and "not generalisable" in result["reasons"][0]

    def test_a_clear_gain_in_every_area_earns_shadow_never_success(self) -> None:
        result = Conclusion.of({"pypi": Kit.card(), "npm": Kit.card()})
        assert result["outcome"] == "shadow" and "never blocking" in result["reasons"][0]

    def test_no_case_ends_in_anything_but_research_or_shadow(self) -> None:
        cases = [
            {"a": None},
            {},
            {"a": Kit.card(mal_blocked=90, mal_n=100)},
            {"a": Kit.card(mal_blocked=303), "b": Kit.card(mal_blocked=303)},
            {"a": Kit.card(), "b": Kit.card(mal_blocked=300)},
            {"a": Kit.card(), "b": Kit.card()},
        ]
        assert {Conclusion.of(c)["outcome"] for c in cases} <= {"research", "shadow"}
