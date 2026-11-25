"""A window report: the confirmed set is the denominator, content recall the headline, advisory matches apart."""

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
    FrozenWindow,
    RescoreRefused,
    WindowReport,
    WindowUnit,
)


class Kit:
    count = 0

    @classmethod
    def unit(cls, caught: str, *labelled: str, **extra) -> WindowUnit:
        cls.count += 1
        return WindowUnit(f"u{cls.count}", frozenset(labelled), caught, **extra)

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
            [Kit.unit(CONTENT_LEARNED, UPSTREAM, caught_without_machine=False)] * 2 + [Kit.unit(CONTENT_HUMAN, UPSTREAM)] * 6
        )
        assert (report["machine_share"]["k"], report["machine_share"]["n"]) == (2, 8)

    def test_advisory_matches_are_in_neither_side_of_it(self) -> None:
        without = Kit.report(
            [Kit.unit(CONTENT_LEARNED, UPSTREAM, caught_without_machine=False), Kit.unit(CONTENT_HUMAN, UPSTREAM)]
        )
        with_advisories = Kit.report(
            [Kit.unit(CONTENT_LEARNED, UPSTREAM, caught_without_machine=False), Kit.unit(CONTENT_HUMAN, UPSTREAM)]
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


class TestAFrozenWindowIsNotScoredByALaterHead:
    """A window's results are frozen at capture with the head and facts version, and a later head may not re-score them."""

    def test_the_freeze_records_the_head_the_facts_version_and_a_digest_of_what_was_scored(
        self,
    ) -> None:
        units = [Kit.unit(CONTENT_HUMAN, UPSTREAM), Kit.unit(NONE, UPSTREAM)]
        frozen = FrozenWindow.freeze(units, "abc1234", "5")
        assert (frozen["head"], frozen["facts_version"], frozen["units"]) == ("abc1234", "5", 2)
        assert len(frozen["digest"]) == 64

    def test_the_same_head_and_facts_may_score_it_again(self) -> None:
        frozen = FrozenWindow.freeze([Kit.unit(NONE, UPSTREAM)], "abc1234", "5")
        assert FrozenWindow.rescore(frozen, "abc1234", "5") is None

    def test_a_later_head_is_refused(self) -> None:
        frozen = FrozenWindow.freeze([Kit.unit(NONE, UPSTREAM)], "abc1234", "5")
        with pytest.raises(RescoreRefused, match="later head"):
            FrozenWindow.rescore(frozen, "def5678", "5")

    def test_another_facts_version_is_refused(self) -> None:
        frozen = FrozenWindow.freeze([Kit.unit(NONE, UPSTREAM)], "abc1234", "5")
        with pytest.raises(RescoreRefused, match="facts version"):
            FrozenWindow.rescore(frozen, "abc1234", "6")

    def test_the_digest_does_not_depend_on_the_order_of_the_units(self) -> None:
        a, b = Kit.unit(CONTENT_HUMAN, UPSTREAM), Kit.unit(NONE, READERS)
        assert FrozenWindow.freeze([a, b], "h", "5") == FrozenWindow.freeze([b, a], "h", "5")


class TestWhatTheReportSaysApart:
    def test_the_first_of_a_family_is_reported_apart_from_its_siblings(self) -> None:
        units = [
            WindowUnit("f1", frozenset({UPSTREAM}), NONE, first_of_family=True),
            WindowUnit("f2", frozenset({UPSTREAM}), NONE, first_of_family=True),
            WindowUnit("s1", frozenset({UPSTREAM}), CONTENT_HUMAN, first_of_family=False),
            WindowUnit("s2", frozenset({UPSTREAM}), CONTENT_HUMAN, first_of_family=False),
            WindowUnit("s3", frozenset({UPSTREAM}), CONTENT_HUMAN, first_of_family=False),
            WindowUnit("u1", frozenset({UPSTREAM}), CONTENT_HUMAN),
        ]
        report = Kit.report(units)
        assert (report["first_of_family_recall"]["k"], report["first_of_family_recall"]["n"]) == (
            0,
            2,
        )
        assert (report["sibling_recall"]["k"], report["sibling_recall"]["n"]) == (3, 3)
        assert report["family_position_unknown"] == 1

    def test_a_unit_with_no_label_is_unknown_in_no_denominator_and_never_benign(self) -> None:
        report = Kit.report([Kit.unit(CONTENT_HUMAN, UPSTREAM), Kit.unit(NONE), Kit.unit(NONE)])
        assert report["unlabelled_unknown"] == 2 and report["denominator"] == 1
        assert report["content_recall"]["value"] == 1.0

    def test_the_never_captured_share_and_the_label_delay_are_recorded(self) -> None:
        units = [
            WindowUnit("a", frozenset({UPSTREAM}), NONE, label_delay_days=2.0),
            WindowUnit("b", frozenset({UPSTREAM}), NONE, label_delay_days=10.0),
            WindowUnit("c", frozenset({UPSTREAM}), NONE, label_delay_days=3.0),
        ]
        report = WindowReport.of(units, "2026-11-01", "2026-11-14", never_captured=1)
        assert report["never_captured_share"] == 0.25 and report["never_captured"] == 1
        assert report["label_delay_days"] == {"median": 3.0, "n": 3}

    def test_with_no_label_delay_known_there_is_none_not_zero(self) -> None:
        assert Kit.report([Kit.unit(NONE, UPSTREAM)])["label_delay_days"] is None


class TestRecallByAttackClass:
    """A fixture window with a new class flags it."""

    def window(self) -> list[WindowUnit]:
        return [
            WindowUnit(
                "a1", frozenset({UPSTREAM}), CONTENT_HUMAN, attack_class="install-script-dropper"
            ),
            WindowUnit("a2", frozenset({UPSTREAM}), NONE, attack_class="install-script-dropper"),
            WindowUnit("b1", frozenset({READERS}), NONE, attack_class="agent-prompt-injection"),
            WindowUnit("t1", frozenset({TEACHER}), NONE, attack_class="teacher-only-class"),
        ]

    def test_each_class_has_its_own_recall(self) -> None:
        report = WindowReport.of(
            self.window(), "a", "b", train_classes=frozenset({"install-script-dropper"})
        )
        assert report["by_class"]["install-script-dropper"]["recall"]["k"] == 1
        assert report["by_class"]["agent-prompt-injection"]["recall"] == {
            "k": 0,
            "n": 1,
            "value": 0.0,
            "low": report["by_class"]["agent-prompt-injection"]["recall"]["low"],
            "high": report["by_class"]["agent-prompt-injection"]["recall"]["high"],
        }

    def test_a_class_absent_from_train_is_flagged_and_a_known_one_is_not(self) -> None:
        report = WindowReport.of(
            self.window(), "a", "b", train_classes=frozenset({"install-script-dropper"})
        )
        assert report["new_classes"] == ["agent-prompt-injection"]
        assert report["by_class"]["install-script-dropper"]["absent_from_train"] is False

    def test_a_class_only_the_teacher_labelled_is_not_in_the_report(self) -> None:
        report = WindowReport.of(self.window(), "a", "b", train_classes=frozenset())
        assert "teacher-only-class" not in report["by_class"]

    def test_with_no_training_classes_given_nothing_is_flagged_and_it_says_not_known(self) -> None:
        report = WindowReport.of(self.window(), "a", "b")
        assert (
            report["new_classes"] == []
            and report["by_class"]["install-script-dropper"]["absent_from_train"] is None
        )
