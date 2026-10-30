"""The CPU time each detector spent in a scan, when asked for: what a capacity question needs first.

A scan that runs for twenty minutes says how long it took (`stats.duration_ms`) but not where the
time went, and a profiler answers that wrongly: cProfile's cost lands on Python-level calls, so it
reported the capability matcher at 363 s on one package where the matcher measured 4.7 s per 10 MiB
window without it (review 98, item D). This records each detector's CPU time, around the one call
every engine runner makes (`Detection.run`, and the worker's `inspect` in `engine/parallel`), and the
scan's stats carry it as `detector_cpu_ms`.

Off unless `CORDON_DETECTOR_CLOCK=1`: a time differs on every run, and a scan's output must not
(`tests/integration/test_hash_order.py`). With it off, nothing is recorded and the stats are byte for
byte what they were. CPU time (`time.process_time`), so a loaded machine does not stretch it.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, ClassVar, TypeVar

from cordon_scanner.foundation.collector import ScanCaches

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

T = TypeVar("T")


class DetectorClock:
    """Per-detector CPU seconds for the scan in progress, in this process."""

    SWITCH: ClassVar[str] = "CORDON_DETECTOR_CLOCK"

    #: Seconds by detector id, for the scan in progress; emptied after each scan.
    _spent: ClassVar[dict[str, float]] = {}

    @staticmethod
    def enabled() -> bool:
        return os.environ.get(DetectorClock.SWITCH) == "1"

    @staticmethod
    def timed(detector_id: str, run: Callable[[], T]) -> T:
        """`run()`, with its CPU time added to `detector_id`'s when the clock is on."""
        if not DetectorClock.enabled():
            return run()
        started = time.process_time()
        try:
            return run()
        finally:
            spent = DetectorClock._spent
            spent[detector_id] = spent.get(detector_id, 0.0) + time.process_time() - started

    @staticmethod
    def add(seconds: Mapping[str, float]) -> None:
        """A worker process's times, added to this process's."""
        spent = DetectorClock._spent
        for detector_id, value in seconds.items():
            spent[detector_id] = spent.get(detector_id, 0.0) + value

    @staticmethod
    def taken() -> dict[str, float]:
        """This process's times so far, removed: what a worker hands back with each unit."""
        taken = dict(DetectorClock._spent)
        DetectorClock._spent.clear()
        return taken

    @staticmethod
    def milliseconds() -> dict[str, int] | None:
        """The scan's times in whole milliseconds by detector id, sorted; None when the clock is off."""
        if not DetectorClock.enabled():
            return None
        return {
            detector_id: int(seconds * 1000)
            for detector_id, seconds in sorted(DetectorClock._spent.items())
        }


ScanCaches.register(DetectorClock._spent)

__all__ = ["DetectorClock"]
