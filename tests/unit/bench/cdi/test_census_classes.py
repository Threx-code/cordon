"""The census classes beyond the first three, on a fixture window of hand-made facts records: no package and no sample is read."""

from __future__ import annotations

import sys

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.census import (
    COUNTED_ONLY,
    DO_NOT_SEPARATE,
    FACTS_EXIST,
    NEW_CLASS,
    NO_SEPARATING_FACT,
    READING_GAP,
    Census,
    MissRow,
    Signature,
    TermSets,
)
from test_census import Kit

TRAIN_CLASSES = {"credential-theft", "dropper"}
PLAIN_TERMS = Signature.of(Kit.contained())
DISTINGUISHING = Signature.of(Kit.separable()) - PLAIN_TERMS


def row(key: str, facts, attack_class: str = "dropper", split: str = "train", tier: str = "confirmed") -> MissRow:
    return MissRow(key, "fam", "npm", split, tier, facts, attack_class)


class TestEachClassRoutesAsSpecifiedOnAFixtureWindow:
    def window(self, **kw):
        misses = [
            row("a-gap", Kit.unread()),
            row("b-contained", Kit.contained()),
            row("c-separable", Kit.separable()),
            row("d-new-class", Kit.separable(), attack_class="clipboard-hijack"),
        ]
        return Census.run("w", misses, Kit.legit(), train_classes=TRAIN_CLASSES, **kw)

    def routes(self, report) -> dict[str, tuple[str, str]]:
        return {v.key: (v.klass, v.route) for v in report.verdicts}

    def test_without_candidate_terms_the_four_classes_route_as_before_and_a_new_class_goes_to_a_reader_or_teacher(self) -> None:
        assert self.routes(self.window()) == {
            "a-gap": (READING_GAP, "reader"),
            "b-contained": (NO_SEPARATING_FACT, "teacher"),
            "c-separable": (FACTS_EXIST, "generators"),
            "d-new-class": (NEW_CLASS, "reader_or_teacher"),
        }

    def test_terms_that_legit_releases_hold_make_a_miss_do_not_separate_and_go_to_the_teacher(self) -> None:
        routes = self.routes(self.window(candidate_terms=PLAIN_TERMS))
        assert routes["c-separable"] == (DO_NOT_SEPARATE, "teacher")

    def test_terms_no_legit_release_holds_leave_the_miss_for_the_generators(self) -> None:
        routes = self.routes(self.window(candidate_terms=DISTINGUISHING))
        assert routes["c-separable"] == (FACTS_EXIST, "generators")

    def test_a_new_class_is_never_a_generator_input(self) -> None:
        report = self.window(candidate_terms=DISTINGUISHING)
        assert [v.key for v in report.for_generators()] == ["c-separable"]

    def test_a_reading_gap_still_comes_before_a_new_class(self) -> None:
        report = Census.run(
            "w", [row("g", Kit.unread(), attack_class="clipboard-hijack")], Kit.legit(), train_classes=TRAIN_CLASSES
        )
        assert report.verdicts[0].klass == READING_GAP

    def test_a_miss_with_no_class_named_is_never_a_new_class(self) -> None:
        report = Census.run("w", [row("x", Kit.separable(), attack_class="")], Kit.legit(), train_classes=TRAIN_CLASSES)
        assert report.verdicts[0].klass == FACTS_EXIST

    def test_without_train_classes_nothing_is_a_new_class(self) -> None:
        report = Census.run("w", [row("x", Kit.separable(), attack_class="anything")], Kit.legit())
        assert report.verdicts[0].klass == FACTS_EXIST

    def test_a_held_miss_of_a_new_class_is_counted_in_its_class_and_goes_nowhere(self) -> None:
        report = Census.run(
            "w",
            [row("h", Kit.separable(), attack_class="clipboard-hijack", split="held")],
            Kit.legit(),
            train_classes=TRAIN_CLASSES,
        )
        assert (report.verdicts[0].klass, report.verdicts[0].route) == (NEW_CLASS, COUNTED_ONLY)

    def test_the_counts_name_every_class(self) -> None:
        counts = self.window(candidate_terms=PLAIN_TERMS).counts()
        assert (counts["reading_gap"], counts["no_separating_fact"], counts["facts_exist_but_do_not_separate"]) == (1, 1, 1)
        assert (counts["new_class"], counts["facts_exist"], counts["fed_to_generators"]) == (1, 0, 0)


class TestGeneratorsGetEachTermSetsLegitRateFirst:
    def test_the_rate_is_the_share_of_legit_releases_holding_every_term(self) -> None:
        rates = TermSets.legit_rates({"common": PLAIN_TERMS, "rare": DISTINGUISHING}, Kit.legit())
        assert rates == {"common": 1.0, "rare": 0.0}

    def test_a_set_one_of_two_legit_releases_holds_is_one_half(self) -> None:
        hooked_only = Signature.of(Kit.legit()[1]) - PLAIN_TERMS
        assert TermSets.legit_rates({"hook": hooked_only}, Kit.legit()) == {"hook": 0.5}

    def test_with_no_legit_releases_every_rate_is_zero(self) -> None:
        assert TermSets.legit_rates({"x": PLAIN_TERMS}, []) == {"x": 0.0}
