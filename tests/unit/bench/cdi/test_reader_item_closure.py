"""A reader item closes only with the closure evidence: scale, linearity, heavy-tail time, legit incomplete rate, and units seen."""

from __future__ import annotations

import copy
import sys

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.census import Census, MissRow
from bench.cdi.reader_items import CLOSED, OPEN, ClosureEvidence, EvidenceRefused, ReaderTracker
from test_census import Kit

TRUNCATED = "OPERATIONAL.FILE.TRUNCATED"
GOOD = {
    "scale": {"mib10_cpu_seconds": 4.0, "tokens1m_cpu_seconds": 6.0, "bound_cpu_seconds": 10.0},
    "linearity": {"small_seconds": 1.0, "large_seconds": 9.0, "size_ratio": 8.0},
    "heavy_tail": {
        "sum_base": 1000.0,
        "sum_candidate": 1050.0,
        "p50_base": 0.4,
        "p50_candidate": 0.4,
        "p99_base": 9.0,
        "p99_candidate": 9.4,
        "timeouts_base": 3,
        "timeouts_candidate": 2,
    },
    "legit_incomplete": {"before": 0.004, "after": 0.004},
    "units_seen": 20,
}


class Helpers:
    @staticmethod
    def tracker_with_open_item() -> ReaderTracker:
        tracker = ReaderTracker()
        miss = MissRow("m", "fam", "npm", "train", "confirmed", Kit.unread())
        tracker.apply("w1", Census.run("w1", [miss], Kit.legit()).verdicts)
        return tracker

    @staticmethod
    def changed(path: list[str], value):
        evidence = copy.deepcopy(GOOD)
        node = evidence
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return evidence


class TestTheClosureRule:
    def test_complete_evidence_has_no_problems(self) -> None:
        assert ClosureEvidence.problems(GOOD) == []

    @pytest.mark.parametrize(
        "path,value,part",
        [
            (["scale", "mib10_cpu_seconds"], 11.0, "scale: mib10_cpu_seconds is 11.0"),
            (["scale", "tokens1m_cpu_seconds"], 99.0, "scale: tokens1m_cpu_seconds is 99.0"),
            (["linearity", "large_seconds"], 20.0, "linearity: the time grows faster"),
            (["heavy_tail", "sum_candidate"], 1101.0, "heavy tail: the ratio of sums is over 1.1"),
            (["legit_incomplete", "after"], 0.005, "legit incomplete: the rate went up"),
            (["units_seen"], 19, "units seen: fewer than 20"),
        ],
    )
    def test_each_part_that_fails_is_named(self, path, value, part) -> None:
        problems = ClosureEvidence.problems(Helpers.changed(path, value))
        assert len(problems) == 1 and problems[0].startswith(part)

    def test_a_ratio_of_exactly_one_point_one_passes(self) -> None:
        assert (
            ClosureEvidence.problems(Helpers.changed(["heavy_tail", "sum_candidate"], 1100.0)) == []
        )

    def test_a_missing_part_is_a_problem_not_a_pass(self) -> None:
        for part in ("scale", "linearity", "heavy_tail", "legit_incomplete", "units_seen"):
            evidence = {k: v for k, v in GOOD.items() if k != part}
            assert ClosureEvidence.problems(evidence), part

    def test_the_heavy_tail_needs_p50_p99_and_the_timeouts_stated(self) -> None:
        tail = {k: v for k, v in GOOD["heavy_tail"].items() if k != "p99_candidate"}
        assert "p99" in ClosureEvidence.problems({**GOOD, "heavy_tail": tail})[0]


class TestAnItemWithTooFewUnitsSeenStaysOpen:
    def test_evidence_with_too_few_units_is_refused_and_the_item_stays_open_after_a_clean_window(
        self,
    ) -> None:
        tracker = Helpers.tracker_with_open_item()
        with pytest.raises(EvidenceRefused, match="fewer than 20 units"):
            tracker.attach_evidence(TRUNCATED, "JS", Helpers.changed(["units_seen"], 12))
        tracker.apply("w2", [])
        item = tracker.items[(TRUNCATED, "JS")]
        assert item.status == OPEN and item.acceptance is None and item.waiting_for_acceptance

    def test_every_part_that_failed_is_in_the_refusal(self) -> None:
        tracker = Helpers.tracker_with_open_item()
        evidence = Helpers.changed(["units_seen"], 3)
        evidence["legit_incomplete"]["after"] = 0.5
        with pytest.raises(EvidenceRefused) as refused:
            tracker.attach_evidence(TRUNCATED, "JS", evidence)
        assert len(refused.value.problems) == 2

    def test_complete_evidence_lets_the_item_close_in_a_later_window_that_no_longer_shows_it(
        self,
    ) -> None:
        tracker = Helpers.tracker_with_open_item()
        reference = tracker.attach_evidence(TRUNCATED, "JS", GOOD)
        tracker.apply("w2", [])
        item = tracker.items[(TRUNCATED, "JS")]
        assert (
            item.status == CLOSED
            and item.acceptance == reference
            and reference.startswith("evidence:")
        )

    def test_evidence_for_an_item_that_does_not_exist_is_refused(self) -> None:
        with pytest.raises(KeyError):
            ReaderTracker().attach_evidence(TRUNCATED, "JS", GOOD)
