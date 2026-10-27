"""The garbage collector relaxed while a scan runs (`foundation/collector`)."""

from __future__ import annotations

import gc
import threading

import pytest

from cordon_scanner.foundation.collector import Collector


class TestCollector:
    CALLER = (700, 10, 10)

    def setup_method(self) -> None:
        self.before = gc.get_threshold()
        gc.set_threshold(*self.CALLER)

    def teardown_method(self) -> None:
        gc.set_threshold(*self.before)

    def test_a_scan_relaxes_the_schedule_and_puts_the_callers_back(self) -> None:
        seen = Collector.during(gc.get_threshold)
        assert seen == Collector.THRESHOLD
        assert gc.get_threshold() == self.CALLER

    def test_nested_scans_restore_once_when_the_outer_ends(self) -> None:
        def outer() -> tuple[int, ...]:
            Collector.during(gc.get_threshold)
            return gc.get_threshold()  # still inside the outer scan

        assert Collector.during(outer) == Collector.THRESHOLD
        assert gc.get_threshold() == self.CALLER

    def test_a_failing_scan_still_restores(self) -> None:
        def fails() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            Collector.during(fails)
        assert gc.get_threshold() == self.CALLER

    def test_concurrent_scans_restore_after_the_last(self) -> None:
        inside, release = threading.Event(), threading.Event()

        def long_scan() -> None:
            inside.set()
            release.wait(10)

        worker = threading.Thread(target=Collector.during, args=(long_scan,))
        worker.start()
        assert inside.wait(10)
        Collector.during(lambda: None)  # a second scan ends while the first runs
        assert gc.get_threshold() == Collector.THRESHOLD
        release.set()
        worker.join(10)
        assert gc.get_threshold() == self.CALLER

    def test_a_worker_keeps_the_relaxed_schedule(self) -> None:
        Collector.relax()
        assert gc.get_threshold() == Collector.THRESHOLD
