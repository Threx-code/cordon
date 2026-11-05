"""The detector clock: each detector's CPU time in a scan's stats, only when asked for."""

from __future__ import annotations

from typing import TYPE_CHECKING

from test_parallel import ParallelFixtures

from cordon_scanner import Scanner
from cordon_scanner.engine.detector_clock import DetectorClock
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


class ClockKit:
    @staticmethod
    def scan(repository: Path, workers: int) -> dict[str, object]:
        config = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=workers)
        )
        return Scanner(config).scan(repository).stats.to_dict()


class TestTheClock(ParallelFixtures):
    def test_off_the_stats_are_what_they_were(
        self, repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DetectorClock.SWITCH, raising=False)
        assert "detector_cpu_ms" not in ClockKit.scan(repository, 1)

    def test_on_a_serial_scan_times_every_detector_that_ran(
        self, repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DetectorClock.SWITCH, "1")
        timed = ClockKit.scan(repository, 1)["detector_cpu_ms"]
        assert isinstance(timed, dict) and timed, timed
        assert all(isinstance(ms, int) and ms >= 0 for ms in timed.values())
        assert list(timed) == sorted(timed)
        assert "capability" in timed

    def test_a_parallel_scan_names_the_same_detectors(
        self, repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DetectorClock.SWITCH, "1")
        serial = ClockKit.scan(repository, 1)["detector_cpu_ms"]
        parallel = ClockKit.scan(repository, 4)["detector_cpu_ms"]
        assert isinstance(serial, dict) and isinstance(parallel, dict)
        # The parallel scan's file detectors ran in its workers: their times came back with the
        # batches. Both scans ran the same detectors, so both name the same ones.
        assert set(parallel) == set(serial)

    def test_a_pool_started_before_the_clock_was_on_still_times_the_scan(
        self, repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A warm pool's workers started with the clock off; the scan that turns it on is still
        timed in them, because the clock follows the scan, not the worker's environment."""
        monkeypatch.delenv(DetectorClock.SWITCH, raising=False)
        ClockKit.scan(repository, 4)  # the pool starts, clock off
        monkeypatch.setenv(DetectorClock.SWITCH, "1")
        serial = ClockKit.scan(repository, 1)["detector_cpu_ms"]
        parallel = ClockKit.scan(repository, 4)["detector_cpu_ms"]
        assert set(parallel) == set(serial)

    def test_each_scan_starts_from_zero(
        self, repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DetectorClock.SWITCH, "1")
        ClockKit.scan(repository, 1)
        assert DetectorClock.milliseconds() == {}
