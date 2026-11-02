"""DetectorRun: one detector over one unit, run to its end. No time budget cuts it, however small
`per_file_timeout` is set (2026-10-31: a run cut on the wall clock gave a load-dependent answer)."""

from __future__ import annotations

import time
from collections.abc import Iterator

from cordon_scanner.detect.base import DetectorRun, FileUnit, ScanContext
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.rules.loader import RuleSet


class Slow:
    """Yields a marker every 20 ms, ten times, and records the deadline it saw."""

    id = "slow"
    seen_deadline: float | None = None

    def inspect(self, unit: FileUnit, ctx: ScanContext) -> Iterator[str]:
        Slow.seen_deadline = ctx.deadline
        for _ in range(10):
            time.sleep(0.02)
            yield "found"


class DetectorRunKit:
    @staticmethod
    def unit() -> FileUnit:
        return FileUnit(content=FileContent(path="a.txt", raw=b"x", size=1))

    @staticmethod
    def ctx(per_file_timeout: float = 5.0) -> ScanContext:
        config = Config.default()
        config = config.with_overrides(
            limits=config.limits.merged(per_file_timeout=per_file_timeout)
        )
        return ScanContext(config=config, rules=RuleSet(()))


class TestDetectorRun:
    def test_a_slow_detector_runs_to_its_end_whatever_the_setting(self) -> None:
        found = DetectorRun.findings(Slow(), DetectorRunKit.unit(), DetectorRunKit.ctx(1e-9))
        assert found == ["found"] * 10

    def test_it_adds_no_deadline_of_its_own(self) -> None:
        DetectorRun.findings(Slow(), DetectorRunKit.unit(), DetectorRunKit.ctx(1e-9))
        assert Slow.seen_deadline is None
