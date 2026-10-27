"""The cyclic garbage collector, relaxed while a scan runs.

A scan creates objects far faster than most programs -- a large JavaScript bundle parses into
millions of syntax nodes -- and the collector's default schedule (a young-generation pass every
700 new objects) then spends a large share of the time re-walking a heap that is still growing:
40% of one 10 MB bundle's parse. A scan raises the young generation's threshold for as long as it
runs and puts the caller's schedule back after, so a program that embeds Cordon keeps its own.
Collection is only delayed, never stopped: cycles are still found and freed.

A worker process exists only to scan, so it keeps the relaxed schedule for its life (`relax`).
"""

from __future__ import annotations

import gc
import threading
from collections.abc import Callable
from typing import Any, ClassVar, TypeVar

T = TypeVar("T")


class Collector:
    """The relaxed schedule, applied for a call or for a process."""

    #: Young-generation threshold while scanning; the older generations keep the default ratios.
    THRESHOLD: ClassVar[tuple[int, int, int]] = (50_000, 10, 10)

    _lock: ClassVar[threading.Lock] = threading.Lock()
    _depth: ClassVar[int] = 0
    _saved: ClassVar[tuple[int, ...] | None] = None

    @staticmethod
    def relax() -> None:
        """For a process that only scans: the relaxed schedule from now on."""
        gc.set_threshold(*Collector.THRESHOLD)

    @staticmethod
    def during(work: Callable[..., T], *args: Any) -> T:
        """`work(*args)` under the relaxed schedule, the one before it restored after. Nested and
        concurrent scans share it: the first to start saves the schedule, the last to end puts it
        back."""
        with Collector._lock:
            if Collector._depth == 0:
                Collector._saved = gc.get_threshold()
                gc.set_threshold(*Collector.THRESHOLD)
            Collector._depth += 1
        try:
            return work(*args)
        finally:
            with Collector._lock:
                Collector._depth -= 1
                if Collector._depth == 0 and Collector._saved is not None:
                    gc.set_threshold(*Collector._saved)
                    Collector._saved = None


__all__ = ["Collector"]
