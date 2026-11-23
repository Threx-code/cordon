"""A retrained model is refused when a never-lose unit goes from blocked to allowed, and the flip report lists the units that changed side in both directions."""

from __future__ import annotations

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
