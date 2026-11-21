"""The miss census and the reading-gap tracker (learning loop rows LL-12 and LL-13), on `facts/v2`-shaped records only: no package
and no sample is read; every record below is hand-made."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.census import (
    COUNTED_ONLY,
    FACTS_EXIST,
    NO_SEPARATING_FACT,
    PACKAGE_FORM,
    READING_GAP,
    UNRECORDED,
    Census,
    MissRow,
    ReadingGaps,
    Signature,
)
from bench.cdi.reader_items import ReaderTracker

from cordon_scanner.report.facts import FACTS_VERSION

TRUNCATED = "OPERATIONAL.FILE.TRUNCATED"
TIMEOUT = "OPERATIONAL.SCAN.TIMEOUT"


class Kit:
    @staticmethod
    def file(
        reached: bool,
        places: list[str],
        caps: list[str],
        *,
        ext: str = "JS",
        unread: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "key": "0" * 16,
            "ext": ext,
            "reached": reached,
            "places": places,
            "reach": "placed" if reached else "unreached",
            "reach_depth": 0,
            "rules": {},
            "suppressed": {},
            "capabilities": caps,
            "unread": unread or [],
        }

    @staticmethod
    def facts(
        files: list[dict[str, Any]],
        *,
        gaps: dict[str, int] | None = None,
        complete: bool = True,
        version: str = FACTS_VERSION,
    ) -> dict[str, Any]:
        return {
            "facts_version": version,
            "complete": complete,
            "content_complete": complete,
            "gaps": gaps or {},
            "package": {"rules": {}, "hooks": []},
            "files": files,
        }

    @staticmethod
    def legit() -> list[dict[str, Any]]:
        """Ordinary packages: an import entry that egresses, with or without an install hook file that reads."""
        plain = Kit.facts([Kit.file(True, ["import_entry"], ["egress"])])
        hooked = Kit.facts(
            [
                Kit.file(True, ["import_entry"], ["egress"]),
                Kit.file(True, ["install_entry"], ["read_file"]),
            ]
        )
        return [plain, hooked]

    @staticmethod
    def contained() -> dict[str, Any]:
        """A miss whose every term a legit package also has."""
        return Kit.facts([Kit.file(True, ["import_entry"], ["egress"])])

    @staticmethod
    def separable() -> dict[str, Any]:
        """A miss with a shape no legit package has: spawn and egress together in a file nothing reaches."""
        return Kit.facts(
            [
                Kit.file(True, ["import_entry"], ["egress"]),
                Kit.file(False, [], ["spawn", "egress"]),
            ]
        )

    @staticmethod
    def unread() -> dict[str, Any]:
        """A miss the scan could not read whole: one file left unread."""
        return Kit.facts(
            [Kit.file(True, ["import_entry"], [], unread=[TRUNCATED])],
            gaps={TRUNCATED: 1},
            complete=False,
        )

    @staticmethod
    def row(
        key: str,
        facts: dict[str, Any],
        *,
        split: str = "train",
        tier: str = "confirmed",
        family: str = "fam",
    ) -> MissRow:
        return MissRow(key, family, "npm", split, tier, facts)


class TestEveryMissGetsOneClassAndRoute:
    """LL-12: a fixture window with one miss of each class routes each correctly."""

    def census(self) -> dict[str, Any]:
        rows = [
            Kit.row("a-gap", Kit.unread(), family="fg"),
            Kit.row("b-same", Kit.contained(), family="fs"),
            Kit.row("c-facts", Kit.separable(), family="ff"),
        ]
        report = Census.run("2026-11-20", rows, Kit.legit())
        return {v.key: v for v in report.verdicts}

    def test_each_class_is_named_and_routed(self) -> None:
        verdicts = self.census()
        assert verdicts["a-gap"].klass == READING_GAP
        assert verdicts["a-gap"].route == "reader"
        assert verdicts["b-same"].klass == NO_SEPARATING_FACT
        assert verdicts["b-same"].route == "teacher"
        assert verdicts["c-facts"].klass == FACTS_EXIST
        assert verdicts["c-facts"].route == "generators"

    def test_only_the_facts_exist_miss_reaches_a_generator(self) -> None:
        rows = [
            Kit.row("a-gap", Kit.unread()),
            Kit.row("b-same", Kit.contained()),
            Kit.row("c-facts", Kit.separable()),
        ]
        report = Census.run("w", rows, Kit.legit())
        assert [v.key for v in report.for_generators()] == ["c-facts"]

    def test_a_reading_gap_comes_before_the_signature(self) -> None:
        # The release that was not read has no signature to compare: a gap in a file that is otherwise like a legit one is still a gap.
        facts = Kit.facts(
            [Kit.file(True, ["import_entry"], ["egress"], unread=[TRUNCATED])],
            gaps={TRUNCATED: 1},
            complete=False,
        )
        (verdict,) = Census.run("w", [Kit.row("m", facts)], Kit.legit()).verdicts
        assert verdict.klass == READING_GAP
        assert verdict.distance is None

    def test_the_counts_are_whole_numbers_with_no_name_in_them(self) -> None:
        rows = [
            Kit.row("a", Kit.unread()),
            Kit.row("b", Kit.contained()),
            Kit.row("c", Kit.separable()),
        ]
        counts = Census.run("w", rows, Kit.legit()).counts()
        assert counts == {
            "misses": 3,
            "stale_facts_version": 0,
            "reading_gap": 1,
            "no_separating_fact": 1,
            "facts_exist": 1,
            "fed_to_generators": 1,
            "held": 0,
        }


class TestTheNearestLegitDistance:
    def test_zero_when_one_legit_release_holds_every_term(self) -> None:
        signature = Signature.of(Kit.contained())
        assert Signature.distance(signature, [Signature.of(f) for f in Kit.legit()]) == 0

    def test_positive_when_the_miss_has_a_term_no_legit_release_has(self) -> None:
        signature = Signature.of(Kit.separable())
        assert Signature.distance(signature, [Signature.of(f) for f in Kit.legit()]) > 0

    def test_a_legit_release_with_more_terms_still_holds_them(self) -> None:
        # The hooked legit release has more terms than the miss; a miss inside it has no separating conjunction.
        miss = Kit.facts([Kit.file(True, ["install_entry"], ["read_file"])])
        assert Signature.distance(Signature.of(miss), [Signature.of(f) for f in Kit.legit()]) == 0

    def test_without_any_legit_release_nothing_is_the_same(self) -> None:
        signature = Signature.of(Kit.contained())
        assert Signature.distance(signature, []) == len(signature)

    def test_the_kinds_a_rule_may_never_use_are_not_in_the_signature(self) -> None:
        assert all(
            term[0] in ("file", "package_rule", "hook") for term in Signature.of(Kit.separable())
        )


class TestReadingGaps:
    def test_an_unread_file_is_its_rule_and_its_form(self) -> None:
        facts = Kit.facts(
            [Kit.file(True, ["import_entry"], [], ext="MJS", unread=[TRUNCATED])],
            gaps={TRUNCATED: 1},
            complete=False,
        )
        assert ReadingGaps.of(facts) == ((TRUNCATED, "MJS"),)

    def test_a_gap_no_file_carries_is_a_package_gap(self) -> None:
        facts = Kit.facts([], gaps={TIMEOUT: 1}, complete=False)
        assert ReadingGaps.of(facts) == ((TIMEOUT, PACKAGE_FORM),)

    def test_a_rule_that_one_file_carries_is_not_also_a_package_gap(self) -> None:
        facts = Kit.facts(
            [Kit.file(True, ["import_entry"], [], unread=[TRUNCATED])],
            gaps={TRUNCATED: 1},
            complete=False,
        )
        assert ReadingGaps.of(facts) == ((TRUNCATED, "JS"),)

    def test_two_forms_of_one_rule_are_two_gaps(self) -> None:
        files = [
            Kit.file(True, ["import_entry"], [], ext="JS", unread=[TRUNCATED]),
            Kit.file(False, [], [], ext="PY", unread=[TRUNCATED]),
        ]
        facts = Kit.facts(files, gaps={TRUNCATED: 2}, complete=False)
        assert ReadingGaps.of(facts) == ((TRUNCATED, "JS"), (TRUNCATED, "PY"))

    def test_an_incomplete_scan_that_recorded_no_rule_is_still_a_gap(self) -> None:
        assert ReadingGaps.of(Kit.facts([], complete=False)) == ((UNRECORDED, PACKAGE_FORM),)

    def test_a_complete_scan_has_none(self) -> None:
        assert ReadingGaps.of(Kit.contained()) == ()


class TestAHeldMissIsCountedNeverFed:
    """SI-Q8 and SI-Q9: only a confirmed or corroborated label in the train or dev split informs anything."""

    @pytest.mark.parametrize("split", ["val", "held", "fresh", "sealed", "excluded"])
    def test_a_miss_outside_train_and_dev_is_counted_with_its_reason_and_routed_nowhere(
        self, split: str
    ) -> None:
        rows = [Kit.row("m", Kit.separable(), split=split)]
        report = Census.run("w", rows, Kit.legit())
        (verdict,) = report.verdicts
        assert verdict.klass == FACTS_EXIST
        assert verdict.route == COUNTED_ONLY
        assert verdict.held == (f"split_{split}",)
        assert report.for_generators() == []
        assert report.counts()["held"] == 1
        assert report.counts()[f"held_split_{split}"] == 1

    def test_a_silver_label_in_train_is_held_for_its_tier(self) -> None:
        rows = [Kit.row("m", Kit.separable(), tier="silver")]
        (verdict,) = Census.run("w", rows, Kit.legit()).verdicts
        assert verdict.route == COUNTED_ONLY
        assert verdict.held == ("label_tier_silver",)

    @pytest.mark.parametrize(
        ("tier", "split", "fed"),
        [
            ("confirmed", "train", True),
            ("corroborated", "dev", True),
            ("silver", "train", False),
            ("confirmed", "held", False),
        ],
    )
    def test_the_four_combinations(self, tier: str, split: str, fed: bool) -> None:
        report = Census.run(
            "w", [Kit.row("m", Kit.separable(), tier=tier, split=split)], Kit.legit()
        )
        assert bool(report.for_generators()) is fed

    def test_a_held_reading_gap_does_not_reach_the_reader(self) -> None:
        (verdict,) = Census.run(
            "w", [Kit.row("m", Kit.unread(), split="sealed")], Kit.legit()
        ).verdicts
        assert verdict.klass == READING_GAP
        assert verdict.route == COUNTED_ONLY

    def test_a_miss_with_a_tier_and_a_split_both_wrong_says_both(self) -> None:
        (verdict,) = Census.run(
            "w", [Kit.row("m", Kit.separable(), tier="silver", split="fresh")], Kit.legit()
        ).verdicts
        assert verdict.held == ("label_tier_silver", "split_fresh")


class TestAFactsVersionIsNotReadAgainstAnother:
    """LL-104: a record of another version is counted and never classified, on either side of the comparison."""

    def test_a_stale_miss_is_counted_not_classified(self) -> None:
        stale = Kit.separable()
        stale["facts_version"] = "1"
        report = Census.run("w", [Kit.row("m", stale)], Kit.legit())
        assert report.verdicts == []
        assert report.counts()["stale_facts_version"] == 1

    def test_stale_legit_records_are_not_a_comparison(self) -> None:
        old = []
        for facts in Kit.legit():
            facts = dict(facts)
            facts["facts_version"] = "1"
            old.append(facts)
        (verdict,) = Census.run("w", [Kit.row("m", Kit.contained())], old).verdicts
        assert verdict.klass == FACTS_EXIST  # nothing of this version to be the same as


class TestTheReaderTracker:
    """LL-13: an item stays open while the gap reappears and closes when it does not."""

    @staticmethod
    def window(tracker: ReaderTracker, name: str, rows: list[MissRow]) -> None:
        tracker.apply(name, Census.run(name, rows, Kit.legit()).verdicts)

    def test_a_gap_opens_an_item_with_its_counts_and_families(self) -> None:
        tracker = ReaderTracker()
        rows = [
            Kit.row("a", Kit.unread(), family="f1"),
            Kit.row("b", Kit.unread(), family="f2"),
            Kit.row("c", Kit.unread(), family="f1"),
        ]
        self.window(tracker, "w1", rows)
        item = tracker.items[(TRUNCATED, "JS")]
        assert (item.status, item.units, item.families, item.opened_window) == (
            "open",
            3,
            ["f1", "f2"],
            "w1",
        )

    def test_it_stays_open_while_the_gap_reappears(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        tracker.attach_acceptance(TRUNCATED, "JS", "tests/reader_fixture::truncated_js")
        self.window(tracker, "w2", [Kit.row("b", Kit.unread())])
        item = tracker.items[(TRUNCATED, "JS")]
        assert item.status == "open"
        assert (item.windows_seen, item.last_seen_window) == (2, "w2")

    def test_it_closes_when_the_next_window_no_longer_shows_it(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        tracker.attach_acceptance(TRUNCATED, "JS", "tests/reader_fixture::truncated_js")
        self.window(tracker, "w2", [Kit.row("b", Kit.separable())])
        item = tracker.items[(TRUNCATED, "JS")]
        assert (item.status, item.closed_window) == ("closed", "w2")

    def test_without_an_acceptance_test_it_stays_open_and_says_it_is_waiting(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        self.window(tracker, "w2", [Kit.row("b", Kit.separable())])
        assert tracker.items[(TRUNCATED, "JS")].status == "open"
        assert tracker.counts() == {"open": 1, "closed": 0, "waiting_for_acceptance": 1}

    def test_a_closed_item_reopens_when_the_gap_shows_again_and_needs_a_new_acceptance(
        self,
    ) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        tracker.attach_acceptance(TRUNCATED, "JS", "t1")
        self.window(tracker, "w2", [])
        self.window(tracker, "w3", [Kit.row("c", Kit.unread())])
        item = tracker.items[(TRUNCATED, "JS")]
        assert (item.status, item.reopened, item.acceptance, item.closed_window) == (
            "open",
            1,
            None,
            None,
        )

    def test_a_window_is_applied_once_and_in_order(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w2", [Kit.row("a", Kit.unread())])
        with pytest.raises(ValueError, match="applied once"):
            self.window(tracker, "w2", [])
        with pytest.raises(ValueError, match="applied once"):
            self.window(tracker, "w1", [])

    def test_a_held_miss_never_opens_an_item(self) -> None:
        tracker = ReaderTracker()
        self.window(
            tracker, "w1", [Kit.row("a", Kit.unread(), split="sealed", family="secret-family")]
        )
        assert tracker.items == {}

    def test_a_held_miss_keeps_an_open_item_open_without_naming_its_family(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread(), family="f1")])
        tracker.attach_acceptance(TRUNCATED, "JS", "t1")
        self.window(tracker, "w2", [Kit.row("b", Kit.unread(), split="held", family="held-family")])
        item = tracker.items[(TRUNCATED, "JS")]
        assert item.status == "open"
        assert (item.units, item.held_units, item.families) == (0, 1, [])

    def test_a_different_form_is_a_different_item(self) -> None:
        tracker = ReaderTracker()
        py = Kit.facts(
            [Kit.file(True, ["import_entry"], [], ext="PY", unread=[TRUNCATED])],
            gaps={TRUNCATED: 1},
            complete=False,
        )
        self.window(tracker, "w1", [Kit.row("a", Kit.unread()), Kit.row("b", py)])
        assert sorted(tracker.items) == [(TRUNCATED, "JS"), (TRUNCATED, "PY")]

    def test_the_state_is_the_same_bytes_for_the_same_windows_and_round_trips(self) -> None:
        first, second = ReaderTracker(), ReaderTracker()
        for tracker in (first, second):
            self.window(tracker, "w1", [Kit.row("a", Kit.unread(), family="f1")])
            tracker.attach_acceptance(TRUNCATED, "JS", "t1")
            self.window(tracker, "w2", [])
        assert first.state() == second.state()
        assert ReaderTracker.of_state(first.state()).state() == first.state()


class TestWhatMutationFoundLoose:
    """The survivors of the first mutation run of `census.py` and `reader_items.py`, each pinned: the order of a report, that a record is
    immutable, either flag of an incomplete scan, a class with no miss counted as zero, a file with no extension class, and the tracker's
    own bookkeeping."""

    def test_the_verdicts_come_in_the_order_of_their_keys(self) -> None:
        rows = [Kit.row(key, Kit.separable()) for key in ("z-last", "a-first", "m-middle")]
        report = Census.run("w", rows, Kit.legit())
        assert [v.key for v in report.verdicts] == ["a-first", "m-middle", "z-last"]

    def test_a_miss_row_and_a_verdict_cannot_be_changed(self) -> None:
        import dataclasses

        row = Kit.row("m", Kit.separable())
        (verdict,) = Census.run("w", [row], Kit.legit()).verdicts
        with pytest.raises(dataclasses.FrozenInstanceError):
            row.key = "other"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            verdict.klass = "x"  # type: ignore[misc]

    @pytest.mark.parametrize("flag", ["complete", "content_complete"])
    def test_either_flag_alone_makes_an_incomplete_scan_a_gap(self, flag: str) -> None:
        facts = Kit.facts([Kit.file(True, ["import_entry"], ["egress"])])
        facts[flag] = False
        assert ReadingGaps.of(facts) == ((UNRECORDED, PACKAGE_FORM),)

    def test_a_class_with_no_miss_is_counted_as_zero(self) -> None:
        counts = Census.run("w", [Kit.row("a", Kit.unread())], Kit.legit()).counts()
        assert (counts["reading_gap"], counts["no_separating_fact"], counts["facts_exist"]) == (
            1,
            0,
            0,
        )

    def test_an_unread_file_with_no_extension_class_is_the_other_form(self) -> None:
        facts = Kit.unread()
        del facts["files"][0]["ext"]
        assert ReadingGaps.of(facts) == ((TRUNCATED, "OTHER"),)


class TestWhatMutationFoundLooseInTheTracker:
    @staticmethod
    def window(tracker: ReaderTracker, name: str, rows: list[MissRow]) -> None:
        tracker.apply(name, Census.run(name, rows, Kit.legit()).verdicts)

    def test_an_item_is_made_with_its_kind_its_form_and_no_held_unit(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        item = tracker.items[(TRUNCATED, "JS")]
        assert (item.kind, item.form, item.held_units) == (TRUNCATED, "JS", 0)

    def test_a_freshly_opened_item_is_not_waiting_for_an_acceptance_test(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        assert tracker.counts() == {"open": 1, "closed": 0, "waiting_for_acceptance": 0}

    def test_an_acceptance_test_for_no_such_item_is_refused(self) -> None:
        with pytest.raises(KeyError, match="no such reader item"):
            ReaderTracker().attach_acceptance(TRUNCATED, "JS", "t1")

    def test_a_closed_item_is_counted_as_closed(self) -> None:
        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        tracker.attach_acceptance(TRUNCATED, "JS", "t1")
        self.window(tracker, "w2", [])
        assert tracker.counts() == {"open": 0, "closed": 1, "waiting_for_acceptance": 0}

    def test_a_verdict_of_another_class_never_touches_an_item_even_with_gaps(self) -> None:
        from bench.cdi.census import Verdict

        odd = Verdict("m", "fam", FACTS_EXIST, ((TRUNCATED, "JS"),), 3, True, (), "generators")
        tracker = ReaderTracker()
        tracker.apply("w1", [odd])
        assert tracker.items == {}

    def test_the_state_is_written_with_sorted_keys(self) -> None:
        import json

        tracker = ReaderTracker()
        self.window(tracker, "w1", [Kit.row("a", Kit.unread())])
        tracker.attach_acceptance(TRUNCATED, "JS", "t1")
        record = json.loads(tracker.state())
        assert list(record) == sorted(record)
        assert list(record["items"][0]) == sorted(record["items"][0])


class TestATrackerIgnoresAVerdictThatDisagreesWithItself:
    def test_a_verdict_of_another_class_routed_to_the_reader_still_opens_nothing(self) -> None:
        from bench.cdi.census import Verdict

        odd = Verdict("m", "fam", FACTS_EXIST, ((TRUNCATED, "JS"),), 3, True, (), "reader")
        tracker = ReaderTracker()
        tracker.apply("w1", [odd])
        assert tracker.items == {}


class TestTheSignatureRefusesTheKindsARuleMayNeverUse:
    def test_a_term_of_a_refused_kind_is_left_out_whatever_follows_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from bench.cdi.census import Signature

        from cordon_scanner.rules.fact_terms import FactTerms

        monkeypatch.setattr(
            FactTerms,
            "of_facts",
            staticmethod(lambda facts: {("host", "example", "x"), ("file", "any", "egress")}),
        )
        assert Signature.of({}) == frozenset({("file", "any", "egress")})
