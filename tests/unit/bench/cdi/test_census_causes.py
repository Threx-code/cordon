"""The census separates the misses that are not failures to detect, and ranks reading gaps by value per CPU second."""

from __future__ import annotations

import sys

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.census import (
    NOT_DETECTION,
    PACKAGE_FORM,
    READING_GAP,
    Census,
    Cost,
    MissRow,
    ReadingGaps,
)
from test_census import Kit

TIMEOUT = "OPERATIONAL.SCAN.TIMEOUT"
MEMORY = "OPERATIONAL.SCAN.MEMORY_LIMIT"
TRUNCATED = "OPERATIONAL.FILE.TRUNCATED"


class Helpers:
    @staticmethod
    def package_gap(rule: str) -> dict:
        return Kit.facts([Kit.file(True, ["import_entry"], [])], gaps={rule: 1}, complete=False)

    @staticmethod
    def row(key: str, facts, **over) -> MissRow:
        return MissRow(
            key,
            "fam",
            "npm",
            over.pop("split", "train"),
            over.pop("tier", "confirmed"),
            facts,
            **over,
        )

    @staticmethod
    def verdict(r: MissRow):
        return Census.run("w", [r], Kit.legit()).verdicts[0]


class TestAMissThatIsNotADetectionFailureIsNotAReadingGap:
    def test_a_harness_fault_is_not_a_reading_gap_even_with_a_gap_in_its_facts(self) -> None:
        v = Helpers.verdict(Helpers.row("h", Kit.unread(), harness_fault=True))
        assert (v.klass, v.cause, v.route) == (NOT_DETECTION, "harness_fault", "none")

    def test_a_harness_fault_with_clean_facts_is_still_not_a_detection_failure(self) -> None:
        assert (
            Helpers.verdict(Helpers.row("h", Kit.separable(), harness_fault=True)).klass
            == NOT_DETECTION
        )

    def test_a_block_that_was_only_advisory_is_not_a_detection_failure(self) -> None:
        assert (
            Helpers.verdict(Helpers.row("a", Kit.separable(), advisory_only=True)).cause
            == "advisory_only"
        )

    def test_a_package_timeout_is_a_timeout_not_a_reading_gap(self) -> None:
        v = Helpers.verdict(Helpers.row("t", Helpers.package_gap(TIMEOUT)))
        assert (v.klass, v.cause) == (NOT_DETECTION, "timeout")

    def test_a_size_ceiling_and_an_incomplete_scan_have_their_own_causes(self) -> None:
        assert (
            Helpers.verdict(Helpers.row("m", Helpers.package_gap(MEMORY))).cause == "size_ceiling"
        )
        assert (
            Helpers.verdict(
                Helpers.row("i", Helpers.package_gap("OPERATIONAL.SCAN.INCOMPLETE"))
            ).cause
            == "incomplete_scan"
        )

    def test_a_file_the_scan_could_not_read_is_still_a_reading_gap(self) -> None:
        v = Helpers.verdict(Helpers.row("g", Kit.unread()))
        assert (v.klass, v.cause) == (READING_GAP, "")

    def test_a_timeout_beside_a_file_gap_stays_a_reading_gap(self) -> None:
        facts = Kit.facts(
            [Kit.file(True, ["import_entry"], [], unread=[TRUNCATED])],
            gaps={TRUNCATED: 1, TIMEOUT: 1},
            complete=False,
        )
        assert Helpers.verdict(Helpers.row("g", facts)).klass == READING_GAP

    def test_the_counts_say_how_many_of_each_cause(self) -> None:
        misses = [
            Helpers.row("a", Helpers.package_gap(TIMEOUT)),
            Helpers.row("b", Helpers.package_gap(TIMEOUT)),
            Helpers.row("c", Kit.unread(), harness_fault=True),
        ]
        counts = Census.run("w", misses, Kit.legit()).counts()
        assert (
            counts["not_detection"],
            counts["cause_timeout"],
            counts["cause_harness_fault"],
        ) == (3, 2, 1)
        assert counts["reading_gap"] == 0

    def test_a_not_detection_miss_reaches_no_reader_and_no_generator(self) -> None:
        report = Census.run("w", [Helpers.row("h", Kit.unread(), harness_fault=True)], Kit.legit())
        assert report.for_generators() == [] and report.verdicts[0].route == "none"

    def test_the_gap_reader_sees_the_gap_the_package_form_names(self) -> None:
        assert ReadingGaps.of(Helpers.package_gap(TIMEOUT)) == ((TIMEOUT, PACKAGE_FORM),)


class TestReadingGapsCarryACostClassAndAreRankedByValuePerCpuSecond:
    def test_the_cost_class_is_cpu_seconds_per_mib(self) -> None:
        assert (
            Helpers.verdict(
                Helpers.row("a", Kit.unread(), cpu_seconds=0.5, size_mib=1.0)
            ).cost_class
            == "cheap"
        )
        assert (
            Helpers.verdict(
                Helpers.row("b", Kit.unread(), cpu_seconds=50.0, size_mib=10.0)
            ).cost_class
            == "moderate"
        )
        assert (
            Helpers.verdict(
                Helpers.row("c", Kit.unread(), cpu_seconds=300.0, size_mib=10.0)
            ).cost_class
            == "heavy"
        )

    def test_a_reading_gap_with_no_cost_measured_is_unknown(self) -> None:
        assert Helpers.verdict(Helpers.row("d", Kit.unread())).cost_class == "unknown"
        assert (
            Cost.klass(Helpers.row("e", Kit.unread(), cpu_seconds=1.0, size_mib=0.0)) == "unknown"
        )

    def test_the_gap_with_more_misses_per_cpu_second_ranks_first(self) -> None:
        cheap = [
            Helpers.row(f"c{i}", Kit.unread(), cpu_seconds=1.0, size_mib=1.0) for i in range(3)
        ]
        costly = [
            Helpers.row(
                f"x{i}",
                Kit.facts(
                    [
                        Kit.file(
                            True,
                            ["import_entry"],
                            [],
                            ext="PY",
                            unread=["OPERATIONAL.PARSER.FAILED"],
                        )
                    ],
                    gaps={"OPERATIONAL.PARSER.FAILED": 1},
                    complete=False,
                ),
                cpu_seconds=100.0,
                size_mib=1.0,
            )
            for i in range(3)
        ]
        rows = {r.key: r for r in cheap + costly}
        ranked = Cost.ranked(Census.run("w", cheap + costly, Kit.legit()).verdicts, rows)
        assert [e["gap"][0] for e in ranked] == [TRUNCATED, "OPERATIONAL.PARSER.FAILED"]
        assert (
            ranked[0]["value_per_cpu_second"] == 1.0 and ranked[1]["value_per_cpu_second"] == 0.01
        )

    def test_a_gap_with_no_cost_is_ranked_after_every_gap_that_has_one(self) -> None:
        priced = [Helpers.row("p", Kit.unread(), cpu_seconds=1000.0, size_mib=1.0)]
        other = Kit.facts(
            [Kit.file(True, ["import_entry"], [], unread=["OPERATIONAL.PARSER.FAILED"])],
            gaps={"OPERATIONAL.PARSER.FAILED": 1},
            complete=False,
        )
        unpriced = [Helpers.row("u", other)]
        rows = {r.key: r for r in priced + unpriced}
        ranked = Cost.ranked(Census.run("w", priced + unpriced, Kit.legit()).verdicts, rows)
        assert [e["gap"][0] for e in ranked] == [TRUNCATED, "OPERATIONAL.PARSER.FAILED"]
        assert ranked[1]["value_per_cpu_second"] is None

    def test_a_miss_held_from_learning_adds_no_value(self) -> None:
        held = [Helpers.row("h", Kit.unread(), split="held", cpu_seconds=1.0, size_mib=1.0)]
        assert Cost.ranked(Census.run("w", held, Kit.legit()).verdicts, {"h": held[0]}) == []
