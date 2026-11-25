"""A file the teacher saw run that the static facts call unreached opens one reader item of the start mechanism class."""

from __future__ import annotations

import sys

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.census import MissRow
from bench.cdi.reader_items import OPEN, ReaderTracker
from bench.cdi.start_path import KIND, StartPaths, UnknownMechanism
from test_census import Kit

KEY = "a" * 16
OTHER = "b" * 16


class Helpers:
    @staticmethod
    def facts():
        unreached = Kit.file(False, [], ["spawn"])
        unreached["key"] = KEY
        reached = Kit.file(True, ["import_entry"], ["egress"])
        reached["key"] = OTHER
        return Kit.facts([reached, unreached])

    @staticmethod
    def observation(executed, split="train", tier="confirmed", key="m1"):
        return {
            "row": MissRow(key, "fam", "npm", split, tier, Helpers.facts()),
            "executed": executed,
        }


class TestAComputedPathStartOpensOneItemOfThatClass:
    def test_one_unreached_file_run_by_a_computed_path_opens_one_item(self) -> None:
        tracker = ReaderTracker()
        verdicts = StartPaths.verdicts(
            [Helpers.observation([{"file": KEY, "mechanism": "computed_path"}])]
        )
        tracker.apply("w1", verdicts)
        assert list(tracker.items) == [(KIND, "computed_path")]
        item = tracker.items[(KIND, "computed_path")]
        assert item.status == OPEN and item.units == 1 and item.families == ["fam"]

    def test_two_units_with_the_same_mechanism_share_the_one_item(self) -> None:
        both = [
            Helpers.observation([{"file": KEY, "mechanism": "computed_path"}], key=k)
            for k in ("m1", "m2")
        ]
        tracker = ReaderTracker()
        tracker.apply("w1", StartPaths.verdicts(both))
        assert len(tracker.items) == 1 and tracker.items[(KIND, "computed_path")].units == 2

    def test_another_mechanism_is_another_item(self) -> None:
        runs = [{"file": KEY, "mechanism": "computed_path"}, {"file": KEY, "mechanism": "eval"}]
        tracker = ReaderTracker()
        tracker.apply("w1", StartPaths.verdicts([Helpers.observation(runs)]))
        assert sorted(tracker.items) == [(KIND, "computed_path"), (KIND, "eval")]


class TestWhatOpensNothing:
    def test_a_file_the_facts_reach_opens_nothing(self) -> None:
        assert (
            StartPaths.verdicts(
                [Helpers.observation([{"file": OTHER, "mechanism": "computed_path"}])]
            )
            == []
        )

    def test_a_file_the_record_does_not_list_opens_nothing(self) -> None:
        assert (
            StartPaths.verdicts([Helpers.observation([{"file": "c" * 16, "mechanism": "eval"}])])
            == []
        )

    def test_a_unit_where_nothing_ran_opens_nothing(self) -> None:
        assert StartPaths.verdicts([Helpers.observation([])]) == []

    def test_a_mechanism_outside_the_list_is_refused(self) -> None:
        with pytest.raises(UnknownMechanism):
            StartPaths.verdicts([Helpers.observation([{"file": KEY, "mechanism": "magic"}])])

    def test_a_held_unit_opens_no_item_and_is_counted_apart(self) -> None:
        verdicts = StartPaths.verdicts(
            [Helpers.observation([{"file": KEY, "mechanism": "computed_path"}], split="held")]
        )
        assert verdicts[0].route == "counted_only"
        tracker = ReaderTracker()
        tracker.apply("w1", verdicts)
        assert tracker.items == {}
