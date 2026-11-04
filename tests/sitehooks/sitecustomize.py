"""Test-only: intel judged a minute after it was built, in every Python process a test starts.

Intel older than its limit makes a scan incomplete (7 days without a feed), so a test reading the
wall clock passed the week after an intel refresh and failed the week after. tests/conftest.py
applies `IntelAtBuild.install()` in the test process, and puts this directory on PYTHONPATH with
CORDON_TEST_INTEL_AT_BUILD=1 so the scanner's own child processes (the MCP server's scans, the CLI
run as a subprocess) judge the same way: they start with -P, not -I, so Python loads this file.
Nothing in the package reads this switch; a test about staleness passes its own `now`, which wins.
"""

from __future__ import annotations

import contextlib
import os
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


if os.environ.get("CORDON_TEST_INTEL_AT_BUILD") == "1":
    # A Python without the scanner on its path has nothing to judge.
    with contextlib.suppress(ImportError):
        IntelAtBuild.install()
