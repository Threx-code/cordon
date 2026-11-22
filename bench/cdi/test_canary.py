"""A batch whose canary deviates is invalidated whole."""

from __future__ import annotations

import pytest
from bench.cdi.canary import BadCanary, Canaries

EXPECTED = {"canary-bad": "blocked", "canary-good": "clear"}


class Kit:
    @staticmethod
    def batch(bad: str = "blocked", good: str = "clear", extra: int = 3) -> list[dict[str, str]]:
        rows = [{"unit": f"u{i}", "outcome": "clear"} for i in range(extra)]
        return rows + [{"unit": "canary-bad", "outcome": bad}, {"unit": "canary-good", "outcome": good}]


class TestADeviatingCanaryInvalidatesTheBatch:
    def test_a_batch_whose_canaries_behave_is_valid(self) -> None:
        assert Canaries.check(Kit.batch(), EXPECTED) == {
            "valid": True,
            "deviating": [],
            "missing": [],
            "canaries": 2,
        }

    def test_a_canary_that_should_be_blocked_but_is_clear_invalidates_the_batch(self) -> None:
        verdict = Canaries.check(Kit.batch(bad="clear"), EXPECTED)
        assert verdict["valid"] is False and verdict["deviating"] == ["canary-bad"]

    def test_a_canary_that_should_be_clear_but_is_blocked_invalidates_the_batch(self) -> None:
        verdict = Canaries.check(Kit.batch(good="blocked"), EXPECTED)
        assert verdict["valid"] is False and verdict["deviating"] == ["canary-good"]

    def test_an_unreadable_canary_is_a_deviation(self) -> None:
        assert Canaries.check(Kit.batch(bad="incomplete"), EXPECTED)["deviating"] == ["canary-bad"]

    def test_a_missing_canary_invalidates_the_batch(self) -> None:
        verdict = Canaries.check(Kit.batch()[:-1], EXPECTED)
        assert verdict["valid"] is False and verdict["missing"] == ["canary-good"]

    def test_the_rows_of_an_invalid_batch_do_not_count_and_the_others_do(self) -> None:
        out = Canaries.keep([Kit.batch(extra=2), Kit.batch(bad="clear", extra=5), Kit.batch(extra=1)], EXPECTED)
        assert len(out["rows"]) == 3 and out["invalidated"] == 1
        assert [v["valid"] for v in out["batches"]] == [True, False, True]

    def test_the_canaries_are_not_part_of_the_rows_that_count(self) -> None:
        assert all(r["unit"] not in EXPECTED for r in Canaries.keep([Kit.batch()], EXPECTED)["rows"])


class TestTheCanariesThemselves:
    def test_a_set_needs_one_that_is_blocked_and_one_that_is_clear(self) -> None:
        with pytest.raises(BadCanary, match="one that must be blocked and one that must be clear"):
            Canaries.declare({"a": "clear", "b": "clear"})

    def test_a_single_canary_is_too_few(self) -> None:
        with pytest.raises(BadCanary, match="at least 2"):
            Canaries.declare({"a": "blocked"})

    def test_an_expected_outcome_must_be_blocked_or_clear(self) -> None:
        with pytest.raises(BadCanary, match="blocked or clear"):
            Canaries.declare({"a": "blocked", "b": "maybe"})

    def test_a_good_set_is_returned_as_declared(self) -> None:
        assert Canaries.declare(EXPECTED) == EXPECTED
