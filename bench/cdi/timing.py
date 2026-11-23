"""The timing record of a paired run: scan times measured on real heavy-tail scans, base against candidate, at equal load.

Time is measured, never worked out. A scan's time is the wall time of the scan itself, taken by the harness; a figure derived from the
facts record (a file count, a size, a rule count) is refused as a source. The two sides must have run at the same load (the same
worker count, memory and CPU limit) and over the same units, or the comparison is refused.

The record states, for each side, the sum of the times, p50, p99 and the number of units that hit the timeout, and the ratio of the
sums (candidate over base). The ratio of sums is what a heavy tail makes honest: a few slow scans decide it, as they decide the cost.
It carries counts and times only, never a unit name."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Final

MEASURED: Final = "scan"
LOAD_KEYS: Final = ("workers", "memory_mib", "cpu_limit")


class TimingRefused(ValueError):
    """The two sets of times cannot be compared: not measured, not at equal load, or not over the same units."""


class Timing:
    @staticmethod
    def percentile(values: Sequence[float], share: float) -> float:
        """The nearest-rank percentile of the values (`share` in 0..1)."""
        ordered = sorted(values)
        return ordered[max(0, math.ceil(share * len(ordered)) - 1)]

    @classmethod
    def side(cls, times: Mapping[str, float], timeout_seconds: float) -> dict[str, Any]:
        values = list(times.values())
        return {
            "units": len(values),
            "sum": round(sum(values), 6),
            "p50": cls.percentile(values, 0.50),
            "p99": cls.percentile(values, 0.99),
            "timeouts": sum(1 for v in values if v >= timeout_seconds),
        }

    @classmethod
    def record(
        cls,
        base: Mapping[str, float],
        candidate: Mapping[str, float],
        *,
        timeout_seconds: float,
        source: str,
        load_base: Mapping[str, Any],
        load_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Times are seconds by unit key. Raises `TimingRefused` unless they were measured on the scan, at equal load, over the same
        units, with every time a positive number."""
        if source != MEASURED:
            raise TimingRefused(f"times come from the scan itself, not from {source!r}")
        if any(load_base.get(k) is None or load_base.get(k) != load_candidate.get(k) for k in LOAD_KEYS):
            raise TimingRefused("the two sides did not run at equal load")
        if set(base) != set(candidate):
            raise TimingRefused("the two sides did not scan the same units")
        if not base:
            raise TimingRefused("there are no scans to time")
        if any(not isinstance(v, (int, float)) or v <= 0 for v in [*base.values(), *candidate.values()]):
            raise TimingRefused("every scan time is a positive number of seconds")
        b, c = cls.side(base, timeout_seconds), cls.side(candidate, timeout_seconds)
        return {
            "base": b,
            "candidate": c,
            "ratio_of_sums": round(c["sum"] / b["sum"], 6),
            "timeout_seconds": timeout_seconds,
            "load": {k: load_base[k] for k in LOAD_KEYS},
        }

    @staticmethod
    def heavy_tail(record: Mapping[str, Any]) -> dict[str, float]:
        """The part of a record that reader-item closure reads."""
        b, c = record["base"], record["candidate"]
        return {
            "sum_base": b["sum"],
            "sum_candidate": c["sum"],
            "p50_base": b["p50"],
            "p50_candidate": c["p50"],
            "p99_base": b["p99"],
            "p99_candidate": c["p99"],
            "timeouts_base": b["timeouts"],
            "timeouts_candidate": c["timeouts"],
        }
