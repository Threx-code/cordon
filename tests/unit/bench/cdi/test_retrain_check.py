"""A retrained model is refused when a never-lose unit goes from blocked to allowed, and the flip report lists the units that changed side in both directions."""

from __future__ import annotations

from typing import ClassVar

from bench.cdi.retrain import RetrainCheck

OLD = {"m1": 0.9, "m2": 0.8, "m3": 0.7, "l1": 0.1, "l2": 0.2, "l3": 0.3}
NEVER_LOSE = {"m1", "m2", "m3"}


class TestTheFlipReport:
    def test_it_lists_both_directions(self) -> None:
        new = {"m1": 0.95, "m2": 0.85, "m3": 0.1, "l1": 0.6, "l2": 0.2, "l3": 0.3}
        report = RetrainCheck.compare(OLD, 0.5, new, 0.5, set())
        assert report.unblocked == ("m3",) and report.newly_blocked == ("l1",)
        assert report.kept_blocked == 2 and report.counts() == {
            "unblocked": 1,
            "newly_blocked": 1,
            "kept_blocked": 2,
            "lost": 0,
        }

    def test_a_model_that_only_adds_blocks_flips_one_way(self) -> None:
        new = {**OLD, "l2": 0.9}
        report = RetrainCheck.compare(OLD, 0.5, new, 0.5, NEVER_LOSE)
        assert report.unblocked == () and report.newly_blocked == ("l2",) and report.refused is None

    def test_the_line_of_each_model_is_its_own(self) -> None:
        report = RetrainCheck.compare(
            OLD, 0.5, {k: v / 2 for k, v in OLD.items()}, 0.25, NEVER_LOSE
        )
        assert report.unblocked == () and report.newly_blocked == () and report.kept_blocked == 3


class TestTheNeverLoseList:
    def test_a_retrain_that_unblocks_a_never_lose_unit_is_refused(self) -> None:
        new = {**OLD, "m3": 0.1}
        report = RetrainCheck.compare(OLD, 0.5, new, 0.5, NEVER_LOSE)
        assert report.refused is not None and report.lost == ("m3",)
        assert report.unblocked == ("m3",)

    def test_a_never_lose_unit_the_new_model_did_not_score_is_lost(self) -> None:
        new = {k: v for k, v in OLD.items() if k != "m2"}
        report = RetrainCheck.compare(OLD, 0.5, new, 0.5, NEVER_LOSE)
        assert report.refused is not None and report.lost == ("m2",)

    def test_a_unit_off_the_list_may_flip_without_a_refusal(self) -> None:
        new = {**OLD, "m3": 0.1}
        report = RetrainCheck.compare(OLD, 0.5, new, 0.5, {"m1", "m2"})
        assert report.refused is None and report.unblocked == ("m3",)

    def test_the_counts_name_no_unit(self) -> None:
        report = RetrainCheck.compare(OLD, 0.5, {**OLD, "m3": 0.1}, 0.5, NEVER_LOSE)
        assert all(isinstance(v, int) for v in report.counts().values())


class TestThresholdsOnlyTightenBetweenRetrains:
    """A retrained model's line for an area may not block more of the established legit units than the last model's line did, counted on the units both scored; units that are not established do not count."""

    ESTABLISHED: ClassVar[set[str]] = {f"e{n}" for n in range(10)}
    OLD: ClassVar[dict[str, dict[str, float]]] = {
        "npm": {**{f"e{n}": n / 10 for n in range(10)}, "new1": 0.99}
    }

    def test_a_line_that_blocks_the_same_or_fewer_established_units_passes(self) -> None:
        tighter = {"npm": {**{f"e{n}": n / 10 for n in range(10)}, "new1": 0.99}}
        assert (
            RetrainCheck.thresholds(self.OLD, {"npm": 0.8}, tighter, {"npm": 0.9}, self.ESTABLISHED)
            == []
        )
        assert (
            RetrainCheck.thresholds(self.OLD, {"npm": 0.8}, tighter, {"npm": 0.8}, self.ESTABLISHED)
            == []
        )

    def test_a_looser_line_is_refused_with_the_counts(self) -> None:
        reasons = RetrainCheck.thresholds(
            self.OLD, {"npm": 0.8}, self.OLD, {"npm": 0.5}, self.ESTABLISHED
        )
        assert reasons == [
            "npm: the new line blocks 5 of 10 established legit units, the last one 2"
        ]

    def test_a_unit_that_is_not_established_is_not_counted(self) -> None:
        looser_only_on_a_new_unit = {"npm": {**self.OLD["npm"], "new1": 0.99}}
        reasons = RetrainCheck.thresholds(
            self.OLD, {"npm": 0.995}, looser_only_on_a_new_unit, {"npm": 0.5}, set()
        )
        assert reasons == []

    def test_an_area_the_new_model_has_no_line_for_is_refused(self) -> None:
        assert RetrainCheck.thresholds(self.OLD, {"npm": 0.8}, self.OLD, {}, self.ESTABLISHED) == [
            "npm: the new model has no line for it"
        ]

    def test_each_area_is_judged_alone(self) -> None:
        old = {"npm": self.OLD["npm"], "pypi": {"p1": 0.9, "p2": 0.2}}
        new = {"npm": self.OLD["npm"], "pypi": {"p1": 0.9, "p2": 0.9}}
        reasons = RetrainCheck.thresholds(
            old,
            {"npm": 0.8, "pypi": 0.8},
            new,
            {"npm": 0.8, "pypi": 0.8},
            {"p1", "p2", *self.ESTABLISHED},
        )
        assert reasons == [
            "pypi: the new line blocks 2 of 2 established legit units, the last one 1"
        ]
