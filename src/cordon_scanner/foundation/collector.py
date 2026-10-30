"""What a scan does to the process around it: the garbage collector relaxed while it runs, and the
caches that hold its files emptied when it returns.

## The collector

The cyclic garbage collector, relaxed while a scan runs.

A scan creates objects far faster than most programs -- a large JavaScript bundle parses into
millions of syntax nodes -- and the collector's default schedule (a young-generation pass every
700 new objects) then spends a large share of the time re-walking a heap that is still growing:
40% of one 10 MB bundle's parse. A scan raises the young generation's threshold for as long as it
runs and puts the caller's schedule back after, so a program that embeds Cordon keeps its own.
Collection is only delayed, never stopped: cycles are still found and freed.

A worker process exists only to scan, so it keeps the relaxed schedule for its life (`relax`).

## The caches

The caches that hold what one scan read, emptied when the scan returns.

Several analyses keep their last few answers process-wide: a file's comment spans by its text, its
documentation by its bytes, a Python file's tree by its source, a rule's glob by the scanned path.
Inside one scan that saves work, since several detectors ask the same of the same file. Across scans
it saves nothing, because the next scan reads other files, and it keeps whole files alive: in one
process that scans unit after unit (the Python API, an editor integration, a measurement harness) the
held memory grew about 0.2 MB a unit and each cache kept its last files at any size. So each such
cache registers here where it is defined, and `Engine.scan` empties them all as it returns.

Emptied under one lock, in one step. A scan running at the same time in another thread loses only
the answers it would have reused: every registered cache is a pure function's memo or keeps the
object its answer belongs to, so emptying one can cost a recomputation and never a wrong answer.

A store keyed by an object's identity takes it through `identity`, and must keep the object itself in
its entry and check it with `is` before answering: an identity is reused once its object is freed, so
an entry that did not hold its object could hand a new object the old one's answer. Going through one
function is what lets a test give a second object the first one's identity.
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


class ScanCaches:
    """Every cache registered as holding a scan's files, and how to empty each."""

    _lock: ClassVar[threading.Lock] = threading.Lock()
    _clearers: ClassVar[list[Callable[[], None]]] = []

    @staticmethod
    def register(cache: T) -> T:
        """`cache` emptied after every scan; returned unchanged, so it stacks as a decorator above
        `functools.lru_cache` or wraps a class-level dict."""
        clear = getattr(cache, "cache_clear", None) or getattr(cache, "clear", None)
        if not callable(clear):
            raise TypeError(f"{cache!r} has neither cache_clear() nor clear()")
        with ScanCaches._lock:
            ScanCaches._clearers.append(clear)
        return cache

    @staticmethod
    def identity(obj: Any) -> int:
        """The key an identity-keyed store files `obj` under: its `id`, through one function."""
        return id(obj)

    @staticmethod
    def after_scan() -> None:
        """Empty every registered cache."""
        with ScanCaches._lock:
            for clear in ScanCaches._clearers:
                clear()

    @staticmethod
    def count() -> int:
        """How many caches are registered."""
        with ScanCaches._lock:
            return len(ScanCaches._clearers)


__all__ = ["Collector", "ScanCaches"]
