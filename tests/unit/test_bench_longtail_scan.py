"""The long-tail scanner reads every archive in its queue, and stops when the scanner is broken.

```
  queue file name           scanned?      why
  ───────────────────────   ──────────    ──────────────────────────────────────────────
  npm/left-pad-1.3.0.tgz    yes           an archive
  rubygems/.omghi-2.gem     yes           a package may start with a dot (it was skipped once)
  npm/x-1.0.0.tgz.part      no            still being written by the fetcher
  .fetch-done               no            the queue's own marker

  first 50 results, >= 90% exit 2 or unparseable  ──▶  stop with exit 3, never record "clean"
```
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))

from longtail_scan import BrokenScanner, LongtailScan


class TestQueued:
    def test_an_archive_is_scanned(self) -> None:
        assert LongtailScan.queued("left-pad-1.3.0.tgz")

    def test_a_package_named_with_a_leading_dot_is_scanned(self) -> None:
        assert LongtailScan.queued(".omghi-2.gem")

    def test_a_file_being_written_is_not(self) -> None:
        assert not LongtailScan.queued("x-1.0.0.tgz.part")

    def test_the_queue_marker_is_not(self) -> None:
        assert not LongtailScan.queued(".fetch-done")


class TestBrokenScanner:
    @staticmethod
    def feed(guard: BrokenScanner, records: list[dict]) -> bool:
        return any(guard.observe(r) for r in records)

    def test_a_run_of_scanner_errors_stops(self) -> None:
        guard = BrokenScanner()
        assert self.feed(guard, [{"exit": 2}] * BrokenScanner.CHECK_AFTER)
        assert "scanner error" in guard.reason()

    def test_unparseable_output_counts_as_a_scanner_error(self) -> None:
        guard = BrokenScanner()
        assert self.feed(guard, [{"exit": 0, "parse_error": "x"}] * BrokenScanner.CHECK_AFTER)

    def test_a_healthy_run_continues(self) -> None:
        guard = BrokenScanner()
        records = [{"exit": 0, "findings": []}] * 45 + [{"exit": 2}] * 5
        assert not self.feed(guard, records)

    def test_the_check_happens_once_then_stays_out_of_the_way(self) -> None:
        guard = BrokenScanner()
        self.feed(guard, [{"exit": 0, "findings": []}] * BrokenScanner.CHECK_AFTER)
        assert not self.feed(guard, [{"exit": 2}] * 500)

    def test_nothing_is_decided_before_enough_results(self) -> None:
        guard = BrokenScanner()
        assert not self.feed(guard, [{"exit": 2}] * (BrokenScanner.CHECK_AFTER - 1))
