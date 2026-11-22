"""The timing record: ratio of sums, p50, p99 and timeouts, measured at equal load, never from facts."""

from __future__ import annotations

import pytest
from bench.cdi.reader_items import ClosureEvidence
from bench.cdi.timing import Timing, TimingRefused

LOAD = {"workers": 4, "memory_mib": 2048, "cpu_limit": 2.0}
BASE = {f"u{i}": 1.0 for i in range(98)} | {"u98": 50.0, "u99": 120.0}
CANDIDATE = {k: v * 1.05 for k, v in BASE.items()}


def record(**over):
    args = {
        "timeout_seconds": 120.0,
        "source": "scan",
        "load_base": LOAD,
        "load_candidate": dict(LOAD),
    }
    args.update(over)
    base = args.pop("base", BASE)
    candidate = args.pop("candidate", CANDIDATE)
    return Timing.record(base, candidate, **args)


class TestTheRecordCarriesRatioOfSumsP50P99AndTimeouts:
    def test_each_side_states_its_sum_p50_p99_and_units_at_the_timeout(self) -> None:
        out = record()
        assert out["base"] == {"units": 100, "sum": 268.0, "p50": 1.0, "p99": 50.0, "timeouts": 1}
        assert out["candidate"]["timeouts"] == 1 and out["candidate"]["p50"] == 1.05

    def test_the_ratio_is_of_the_sums_candidate_over_base(self) -> None:
        assert record()["ratio_of_sums"] == 1.05

    def test_one_slow_scan_decides_a_ratio_of_sums_that_a_median_would_hide(self) -> None:
        slow = dict(CANDIDATE) | {"u99": 400.0}
        out = record(candidate=slow)
        assert out["candidate"]["p50"] == 1.05 and out["ratio_of_sums"] > 1.10

    def test_the_record_closes_a_reader_item_only_through_the_same_rule(self) -> None:
        tail = Timing.heavy_tail(record())
        assert tail["sum_candidate"] / tail["sum_base"] <= 1.10
        evidence = {
            "scale": {"mib10_cpu_seconds": 1.0, "tokens1m_cpu_seconds": 1.0, "bound_cpu_seconds": 10.0},
            "linearity": {"small_seconds": 1.0, "large_seconds": 8.0, "size_ratio": 8.0},
            "heavy_tail": tail,
            "legit_incomplete": {"before": 0.0, "after": 0.0},
            "units_seen": 100,
        }
        assert ClosureEvidence.problems(evidence) == []

    def test_a_record_names_no_unit(self) -> None:
        assert "u99" not in str(record())


class TestTimeIsMeasuredNeverWorkedOut:
    @pytest.mark.parametrize("source", ["facts", "estimate", "", "file_count"])
    def test_a_time_not_taken_from_the_scan_is_refused(self, source: str) -> None:
        with pytest.raises(TimingRefused, match="not from"):
            record(source=source)

    def test_sides_at_different_load_are_refused(self) -> None:
        with pytest.raises(TimingRefused, match="equal load"):
            record(load_candidate={**LOAD, "workers": 8})

    def test_a_load_that_is_not_stated_is_refused(self) -> None:
        with pytest.raises(TimingRefused, match="equal load"):
            record(load_base={"workers": 4}, load_candidate={"workers": 4})

    def test_sides_over_different_units_are_refused(self) -> None:
        with pytest.raises(TimingRefused, match="same units"):
            record(candidate={k: v for k, v in CANDIDATE.items() if k != "u1"})

    def test_a_time_that_is_not_positive_is_refused(self) -> None:
        with pytest.raises(TimingRefused, match="positive"):
            record(candidate=dict(CANDIDATE) | {"u1": 0})

    def test_no_scans_is_refused(self) -> None:
        with pytest.raises(TimingRefused, match="no scans"):
            record(base={}, candidate={})
