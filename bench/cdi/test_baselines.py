"""A second malicious version is compared with the last clean one, not with the first malicious one."""

from __future__ import annotations

import pytest
from bench.cdi.baselines import CLEAN, MALICIOUS, UNLABELLED, PairBaseline, Release


class Helpers:
    @staticmethod
    def release(
        version: int, label: str, *, established: bool = False, caught: bool = False, package: str = "p"
    ) -> Release:
        return Release(package, f"1.{version}", version, label, established, caught)




class TestTheBaseline:
    def history(self) -> list[Release]:
        return [
            Helpers.release(1, CLEAN, established=True),
            Helpers.release(2, CLEAN),  # clean, but the publisher's history is too short to trust it
            Helpers.release(3, UNLABELLED),
            Helpers.release(4, MALICIOUS),
            Helpers.release(5, MALICIOUS),
            Helpers.release(6, CLEAN, established=True),
            Helpers.release(7, MALICIOUS),
        ]

    def test_a_second_malicious_version_is_compared_with_the_last_clean_one_not_the_first_malicious(
        self,
    ) -> None:
        history = self.history()
        second = history[4]
        assert PairBaseline.baseline(history, second).version == "1.1"  # type: ignore[union-attr]

    def test_the_first_malicious_version_has_the_same_baseline(self) -> None:
        history = self.history()
        assert PairBaseline.baseline(history, history[3]).version == "1.1"  # type: ignore[union-attr]

    def test_a_clean_version_that_is_not_established_an_unlabelled_one_and_a_malicious_one_are_passed_over(
        self,
    ) -> None:
        history = self.history()
        assert PairBaseline.baseline(history, history[3]).order == 1  # type: ignore[union-attr]

    def test_a_later_established_clean_version_becomes_the_baseline_of_what_follows_it(
        self,
    ) -> None:
        history = self.history()
        assert PairBaseline.baseline(history, history[6]).version == "1.6"  # type: ignore[union-attr]

    def test_a_version_with_nothing_clean_before_it_has_no_baseline(self) -> None:
        assert (
            PairBaseline.baseline(
                [Helpers.release(1, MALICIOUS), Helpers.release(2, MALICIOUS)], Helpers.release(2, MALICIOUS)
            )
            is None
        )

    def test_another_packages_clean_version_is_never_a_baseline(self) -> None:
        other = Helpers.release(1, CLEAN, established=True, package="other")
        assert PairBaseline.baseline([other, Helpers.release(2, MALICIOUS)], Helpers.release(2, MALICIOUS)) is None

    def test_a_label_that_is_not_one_of_the_three_is_refused(self) -> None:
        with pytest.raises(ValueError):
            Helpers.release(1, "probably")


class TestRecallToldApart:
    def test_the_first_malicious_version_and_the_later_ones_are_separate_figures(self) -> None:
        history = [
            Helpers.release(1, CLEAN, established=True),
            Helpers.release(2, MALICIOUS, caught=False),
            Helpers.release(3, MALICIOUS, caught=True),
            Helpers.release(4, MALICIOUS, caught=True),
        ]
        report = PairBaseline.recall(history)
        assert (report["first_malicious"]["k"], report["first_malicious"]["n"]) == (0, 1)
        assert (report["later_malicious"]["k"], report["later_malicious"]["n"]) == (2, 2)

    def test_a_malicious_version_with_no_baseline_is_counted_on_its_own_line_and_in_neither_figure(
        self,
    ) -> None:
        report = PairBaseline.recall(
            [Helpers.release(1, MALICIOUS, caught=True), Helpers.release(2, MALICIOUS, caught=True)]
        )
        assert report == {"first_malicious": None, "later_malicious": None, "without_baseline": 2}

    def test_each_package_has_its_own_first_malicious_version(self) -> None:
        history = [
            Helpers.release(1, CLEAN, established=True, package="a"),
            Helpers.release(2, MALICIOUS, caught=True, package="a"),
            Helpers.release(1, CLEAN, established=True, package="b"),
            Helpers.release(2, MALICIOUS, caught=False, package="b"),
        ]
        report = PairBaseline.recall(history)
        assert (report["first_malicious"]["k"], report["first_malicious"]["n"]) == (1, 2)
        assert report["later_malicious"] is None
