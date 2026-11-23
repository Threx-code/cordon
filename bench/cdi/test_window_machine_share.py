"""The machine share counts a catch only when removing the machine-made rules turns it into a miss; time to catch is censored."""

from __future__ import annotations

import pytest
from bench.cdi.window import (
    ADVISORY,
    CONTENT_HUMAN,
    CONTENT_LEARNED,
    NONE,
    UPSTREAM,
    TimeToCatch,
    WindowReport,
    WindowUnit,
)


class Kit:
    count = 0

    @classmethod
    def unit(cls, caught: str, **extra) -> WindowUnit:
        cls.count += 1
        return WindowUnit(f"u{cls.count}", frozenset({UPSTREAM}), caught, **extra)

    @classmethod
    def report(cls, units: list[WindowUnit]) -> dict:
        return WindowReport.of(units, "2026-11-01", "2026-11-14")


class TestMachineShareByRemoval:
    def test_a_learned_catch_that_a_human_rule_also_makes_is_not_machine_made(self) -> None:
        report = Kit.report(
            [
                Kit.unit(CONTENT_LEARNED, caught_without_machine=True),
                Kit.unit(CONTENT_LEARNED, caught_without_machine=False),
                Kit.unit(CONTENT_HUMAN),
            ]
        )
        assert (report["machine_share"]["k"], report["machine_share"]["n"]) == (1, 3)

    def test_a_learned_catch_whose_removal_scan_was_not_run_is_counted_apart_and_is_not_machine_made(self) -> None:
        report = Kit.report([Kit.unit(CONTENT_LEARNED), Kit.unit(CONTENT_HUMAN)])
        assert report["machine_share"]["k"] == 0 and report["machine_share_unmeasured"] == 1

    def test_every_learned_catch_with_a_human_rule_beside_it_gives_a_share_of_zero(self) -> None:
        report = Kit.report([Kit.unit(CONTENT_LEARNED, caught_without_machine=True)] * 5)
        assert report["machine_share"]["value"] == 0.0

    def test_a_human_catch_is_never_machine_made_whatever_the_flag(self) -> None:
        assert not Kit.unit(CONTENT_HUMAN, caught_without_machine=False).machine_made

    def test_an_advisory_match_is_in_neither_side(self) -> None:
        report = Kit.report([Kit.unit(ADVISORY, caught_without_machine=False), Kit.unit(CONTENT_HUMAN)])
        assert report["machine_share"]["n"] == 1


class TestTheLimit:
    @staticmethod
    def timed(hours: float | None, watched: float | None = None) -> WindowUnit:
        return Kit.unit(CONTENT_HUMAN if hours is not None else NONE, hours_to_catch=hours, watched_hours=watched)

    @pytest.mark.parametrize("hours", [24.0, 168.0])
    def test_a_catch_exactly_at_the_limit_counts_within_it(self, hours: float) -> None:
        assert TimeToCatch.within([TestTheLimit.timed(hours)], hours)["k"] == 1




class TestTimeToCatchIsCensored:
    def test_the_shares_within_a_day_and_a_week_and_the_uncaught_fraction(self) -> None:
        units = [TestTheLimit.timed(2.0), TestTheLimit.timed(10.0), TestTheLimit.timed(30.0), TestTheLimit.timed(100.0), TestTheLimit.timed(None, 200.0)]
        out = TimeToCatch.of(units)
        assert (out["within_24h"]["k"], out["within_24h"]["n"]) == (2, 5)
        assert (out["within_7d"]["k"], out["within_7d"]["n"]) == (4, 5)
        assert (out["uncaught"]["k"], out["uncaught"]["n"]) == (1, 5)

    def test_a_unit_watched_for_less_than_a_week_and_uncaught_is_not_a_miss_within_the_week(self) -> None:
        units = [TestTheLimit.timed(2.0), TestTheLimit.timed(None, 48.0)]
        out = TimeToCatch.of(units)
        assert (out["within_7d"]["k"], out["within_7d"]["n"]) == (1, 1)
        assert (out["within_24h"]["k"], out["within_24h"]["n"]) == (1, 2)

    def test_the_median_is_a_kaplan_meier_median_over_the_scanners(self) -> None:
        units = [TestTheLimit.timed(1.0), TestTheLimit.timed(2.0), TestTheLimit.timed(3.0), TestTheLimit.timed(4.0)]
        assert TimeToCatch.median(units) == 2.0

    def test_a_censored_unit_leaves_the_risk_set_and_moves_the_median_later(self) -> None:
        plain = [TestTheLimit.timed(1.0), TestTheLimit.timed(2.0), TestTheLimit.timed(3.0), TestTheLimit.timed(4.0)]
        censored = [TestTheLimit.timed(1.0), TestTheLimit.timed(None, 1.5), TestTheLimit.timed(3.0), TestTheLimit.timed(4.0)]
        assert TimeToCatch.median(censored) == 3.0 and TimeToCatch.median(plain) == 2.0

    def test_when_fewer_than_half_were_caught_there_is_no_median(self) -> None:
        assert TimeToCatch.median([TestTheLimit.timed(5.0), TestTheLimit.timed(None, 100.0), TestTheLimit.timed(None, 100.0)]) is None

    def test_units_with_no_watch_time_are_not_in_it(self) -> None:
        assert TimeToCatch.of([Kit.unit(NONE)])["watched"] == 0

    def test_it_is_in_the_window_report(self) -> None:
        report = Kit.report([TestTheLimit.timed(2.0), TestTheLimit.timed(None, 200.0)])
        assert report["time_to_catch"]["uncaught"]["k"] == 1


