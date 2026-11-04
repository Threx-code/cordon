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
runs that code; dune.py read 14% with its conformance cases passing, 68% from one scan with this
(4 Nov). Without coverage running, the save finds no instance and does nothing.
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
    @staticmethod
    def install() -> None:
        from cordon_scanner.engine.isolation.supervisor import WorkerMain

        if getattr(WorkerMain.resolve, "_saves_coverage", False):
            return
        real = WorkerMain.resolve

        def resolve(name):  # type: ignore[no-untyped-def]
            target = real(name)

            def measured(*args, **kwargs):  # type: ignore[no-untyped-def]
                try:
                    return target(*args, **kwargs)
                finally:
                    coverage = sys.modules.get("coverage")
                    current = coverage.Coverage.current() if coverage else None
                    if current is not None:
                        with contextlib.suppress(Exception):
                            current.save()

            return measured

        resolve._saves_coverage = True  # type: ignore[attr-defined]
        WorkerMain.resolve = staticmethod(resolve)  # type: ignore[method-assign]


# Unconditional: coverage starts after this file runs, and a worker forked from this process
# inherits the patch.
with contextlib.suppress(ImportError):
    CoverageInWorkers.install()

if os.environ.get("CORDON_TEST_INTEL_AT_BUILD") == "1":
    # A Python without the scanner on its path has nothing to judge.
    with contextlib.suppress(ImportError):
        IntelAtBuild.install()
