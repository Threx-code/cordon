"""Test-only hooks for every Python process a test starts.

`IntelAtBuild`: intel judged a minute after it was built.

Intel older than its limit makes a scan incomplete (7 days without a feed), so a test reading the
wall clock passed the week after an intel refresh and failed the week after. tests/conftest.py
applies `IntelAtBuild.install()` in the test process, and puts this directory on PYTHONPATH with
CORDON_TEST_INTEL_AT_BUILD=1 so the scanner's own child processes (the MCP server's scans, the CLI
run as a subprocess) judge the same way: they start with -P, not -I, so Python loads this file.
Nothing in the package reads this switch; a test about staleness passes its own `now`, which wins.

`CoverageInWorkers`: a scan worker's coverage saved after each unit it runs. On Linux a worker is
forked from the scan's template and ended by SIGKILL (the supervisor's kill, the parent-death
signal) or `os._exit`, so coverage, which saves at a normal exit, kept nothing a worker ran: the
ecosystem parsers, the context worker, the detectors. The coverage job read 83% for a suite that
runs that code; dune.py read 14% with its conformance cases passing (4 Nov). A worker saves as it
stops, and every few seconds while it runs. Without coverage running, nothing is saved.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time


class IntelAtBuild:
    @staticmethod
    def install() -> None:
        from cordon_scanner.intel.malware.feed import FeedClient

        if getattr(FeedClient.status, "_judged_at_build", False):
            return
        real = FeedClient.status

        def status(*, use_feed, max_age, feed=None, now=None):  # type: ignore[no-untyped-def]
            if now is None:
                probe = real(use_feed=use_feed, max_age=max_age, feed=feed, now=time.time())
                if probe.age_seconds is not None:
                    now = time.time() - probe.age_seconds + 60
            return real(use_feed=use_feed, max_age=max_age, feed=feed, now=now)

        status._judged_at_build = True  # type: ignore[attr-defined]
        FeedClient.status = staticmethod(status)  # type: ignore[method-assign,assignment]


class CoverageInWorkers:
    #: Seconds between saves while a worker runs: saved after every unit, the coverage job took
    #: 153 minutes against 61 (4 Nov). A worker that stops normally saves on its way out, so only a
    #: killed worker loses anything, and at most this much of what it ran.
    INTERVAL = 5.0

    @staticmethod
    def save(force: bool = False) -> None:
        coverage = sys.modules.get("coverage")
        current = coverage.Coverage.current() if coverage else None
        if current is None:
            return
        now = time.monotonic()
        if force or now - CoverageInWorkers._last >= CoverageInWorkers.INTERVAL:
            CoverageInWorkers._last = now
            with contextlib.suppress(Exception):
                current.save()

    _last = 0.0

    @staticmethod
    def install() -> None:
        from cordon_scanner.engine.isolation.supervisor import WorkerMain

        if getattr(WorkerMain.resolve, "_saves_coverage", False):
            return
        real_resolve, real_run = WorkerMain.resolve, WorkerMain.run

        def resolve(name):  # type: ignore[no-untyped-def]
            target = real_resolve(name)

            def measured(*args, **kwargs):  # type: ignore[no-untyped-def]
                try:
                    return target(*args, **kwargs)
                finally:
                    CoverageInWorkers.save()

            return measured

        def run(*args, **kwargs):  # type: ignore[no-untyped-def]
            try:
                return real_run(*args, **kwargs)
            finally:
                CoverageInWorkers.save(force=True)  # told to stop: everything it ran

        resolve._saves_coverage = True  # type: ignore[attr-defined]
        # Named as the methods they replace: a spawned worker is started by pickling `WorkerMain.run`
        # by name, and a local function's name cannot be found (25 failures, 5 Nov).
        for wrapper, real in ((resolve, real_resolve), (run, real_run)):
            wrapper.__module__, wrapper.__qualname__ = real.__module__, real.__qualname__
        WorkerMain.resolve = staticmethod(resolve)  # type: ignore[method-assign]
        WorkerMain.run = staticmethod(run)  # type: ignore[method-assign]


# Only where coverage measures: a child the suite starts under coverage carries
# COVERAGE_PROCESS_CONFIG (pyproject's patch = subprocess), and the pytest process has imported
# coverage by the time tests/conftest.py runs this file. Installed everywhere, it imported the
# scanner's engine at the start of every Python process the suite starts, and the latency job ran
# past two hours (4 Nov). A worker forked from an installed process inherits the patch.
if "COVERAGE_PROCESS_CONFIG" in os.environ or "coverage" in sys.modules:
    with contextlib.suppress(ImportError):
        CoverageInWorkers.install()

if os.environ.get("CORDON_TEST_INTEL_AT_BUILD") == "1":
    # A Python without the scanner on its path has nothing to judge.
    with contextlib.suppress(ImportError):
        IntelAtBuild.install()
