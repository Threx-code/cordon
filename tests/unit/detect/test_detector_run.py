"""DetectorRun: one detector over one unit within the per-file budget (review 27, the budget rule)."""

from __future__ import annotations

import time
from collections.abc import Iterator

from cordon_scanner.detect.base import DetectorRun, FileUnit, ScanContext
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.rules.loader import RuleSet


class Slow:
    """Yields a marker every 50 ms for as long as it is let run, and records the deadline it saw."""

    id = "slow"
    seen_deadline: float | None = None

    def inspect(self, unit: FileUnit, ctx: ScanContext) -> Iterator[str]:
        Slow.seen_deadline = ctx.deadline
        for _ in range(100):
            time.sleep(0.05)
            yield "found"


class Quick:
    id = "quick"

    def inspect(self, unit: FileUnit, ctx: ScanContext) -> Iterator[str]:
        yield "found"


class DetectorRunKit:
    @staticmethod
    def unit() -> FileUnit:
        return FileUnit(content=FileContent(path="a.txt", raw=b"x", size=1))

    @staticmethod
    def ctx() -> ScanContext:
        return ScanContext(config=Config.default(), rules=RuleSet(()))


class TestDetectorRun:
    def test_a_detector_past_its_budget_is_stopped_and_says_so(self) -> None:
        started = time.monotonic()
        found, finished = DetectorRun.findings(
            Slow(), DetectorRunKit.unit(), DetectorRunKit.ctx(), 0.2
        )
        assert not finished
        assert 1 <= len(found) < 100
        assert time.monotonic() - started < 2.0

    def test_the_context_carries_the_budget_s_deadline(self) -> None:
        before = time.monotonic()
        DetectorRun.findings(Slow(), DetectorRunKit.unit(), DetectorRunKit.ctx(), 0.1)
        assert Slow.seen_deadline is not None
        assert before < Slow.seen_deadline <= time.monotonic() + 0.1

    def test_an_earlier_scan_deadline_is_kept(self) -> None:
        earlier = time.monotonic() + 0.05
        ctx = DetectorRunKit.ctx()
        ctx = ScanContext(config=ctx.config, rules=ctx.rules, deadline=earlier)
        DetectorRun.findings(Slow(), DetectorRunKit.unit(), ctx, 10.0)
        assert Slow.seen_deadline == earlier

    def test_a_quick_detector_finishes(self) -> None:
        found, finished = DetectorRun.findings(
            Quick(), DetectorRunKit.unit(), DetectorRunKit.ctx(), 5.0
        )
        assert finished
        assert found == ["found"]

    def test_a_zero_budget_is_no_bound(self) -> None:
        found, finished = DetectorRun.findings(
            Quick(), DetectorRunKit.unit(), DetectorRunKit.ctx(), 0
        )
        assert finished
        assert found == ["found"]
