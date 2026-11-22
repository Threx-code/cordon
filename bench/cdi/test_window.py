"""A window's report: the confirmed set is the denominator, content recall is the headline, machine share leaves out G1."""

from __future__ import annotations

import pytest
from bench.cdi.gate import Gate
from bench.cdi.window import (
    ADVISORY,
    CONTENT_HUMAN,
    CONTENT_LEARNED,
    NONE,
    READERS,
    TEACHER,
    UPSTREAM,
    WindowReport,
    WindowUnit,
)


class Kit:
    count = 0

    @classmethod
    def unit(cls, caught: str, *labelled: str) -> WindowUnit:
        cls.count += 1
        return WindowUnit(f"u{cls.count}", frozenset(labelled), caught)

    @classmethod
    def report(cls, units: list[WindowUnit]) -> dict:
        return WindowReport.of(units, "2026-11-01", "2026-11-14")


class TestTheDenominator:
    """The recall denominator is the upstream-confirmed set: it excludes labels only the teacher gave."""

    def test_units_labelled_by_an_advisory_or_by_two_readers_are_the_denominator(self) -> None:
        report = Kit.report(
            [
                Kit.unit(CONTENT_HUMAN, UPSTREAM),
                Kit.unit(NONE, READERS),
                Kit.unit(NONE, UPSTREAM, TEACHER),
            ]
        )
        assert report["denominator"] == 3

    def test_a_unit_only_the_teacher_labelled_is_not_in_it(self) -> None:
        report = Kit.report(
            [
                Kit.unit(CONTENT_HUMAN, UPSTREAM),
                Kit.unit(CONTENT_HUMAN, TEACHER),
                Kit.unit(NONE, TEACHER),
            ]
        )
        assert report["denominator"] == 1
        assert report["content_recall"]["n"] == 1 and report["teacher_only"]["excluded"] == 2

    def test_a_teacher_confirmation_of_a_release_already_blocked_is_not_new_learning(self) -> None:
        report = Kit.report(
            [
                Kit.unit(CONTENT_HUMAN, TEACHER),
                Kit.unit(ADVISORY, TEACHER),
                Kit.unit(NONE, TEACHER),
                Kit.unit(NONE, TEACHER),
            ]
        )
        assert report["teacher_only"] == {"excluded": 4, "already_blocked": 2, "new_learning": 2}

    def test_with_no_confirmed_unit_there_is_no_recall_at_all_not_a_zero(self) -> None:
        report = Kit.report([Kit.unit(CONTENT_HUMAN, TEACHER)])
        assert (
            report["denominator"] == 0
            and report["content_recall"] is None
            and report["advisory_catches"] is None
        )


class TestTheHeadlineIsContentOnly:
    def test_a_window_report_carries_both_numbers_apart(self) -> None:
        units = (
            [Kit.unit(CONTENT_HUMAN, UPSTREAM)] * 6
            + [Kit.unit(ADVISORY, UPSTREAM)] * 3
            + [Kit.unit(NONE, UPSTREAM)]
        )
        report = Kit.report(units)
        assert (report["content_recall"]["k"], report["content_recall"]["n"]) == (6, 10)
        assert (report["advisory_catches"]["k"], report["advisory_catches"]["n"]) == (3, 10)
        assert report["advisory_counts_as_learning"] is False

    def test_an_advisory_catch_never_raises_the_headline(self) -> None:
        base = [Kit.unit(CONTENT_HUMAN, UPSTREAM), Kit.unit(NONE, UPSTREAM)]
        more = [*base, Kit.unit(ADVISORY, UPSTREAM)]
        assert (
            Kit.report(more)["content_recall"]["k"] == Kit.report(base)["content_recall"]["k"] == 1
        )

    def test_the_interval_is_the_gates_own(self) -> None:
        report = Kit.report([Kit.unit(CONTENT_HUMAN, UPSTREAM)] * 19 + [Kit.unit(NONE, UPSTREAM)])
        figure = report["content_recall"]
        assert figure["value"] == pytest.approx(0.95)
        assert (figure["low"], figure["high"]) == Gate.wilson(19, 20)


class TestMachineShareLeavesOutTheAdvisories:
    def test_it_is_learned_catches_over_content_catches(self) -> None:
        report = Kit.report(
            [Kit.unit(CONTENT_LEARNED, UPSTREAM)] * 2 + [Kit.unit(CONTENT_HUMAN, UPSTREAM)] * 6
        )
        assert (report["machine_share"]["k"], report["machine_share"]["n"]) == (2, 8)

    def test_advisory_matches_are_in_neither_side_of_it(self) -> None:
        without = Kit.report(
            [Kit.unit(CONTENT_LEARNED, UPSTREAM), Kit.unit(CONTENT_HUMAN, UPSTREAM)]
        )
        with_advisories = Kit.report(
            [Kit.unit(CONTENT_LEARNED, UPSTREAM), Kit.unit(CONTENT_HUMAN, UPSTREAM)]
            + [Kit.unit(ADVISORY, UPSTREAM)] * 40
        )
        assert with_advisories["machine_share"] == without["machine_share"]

    def test_a_window_with_only_advisory_catches_has_no_machine_share(self) -> None:
        assert Kit.report([Kit.unit(ADVISORY, UPSTREAM)])["machine_share"] is None


class TestWhatAUnitMustBe:
    def test_an_unknown_catcher_or_label_source_is_refused(self) -> None:
        with pytest.raises(ValueError):
            WindowUnit("u", frozenset({UPSTREAM}), "luck")
        with pytest.raises(ValueError):
            WindowUnit("u", frozenset({"rumour"}), NONE)
