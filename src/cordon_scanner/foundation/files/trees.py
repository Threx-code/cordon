"""Removing a working directory, on every operating system.

`shutil.rmtree(path, ignore_errors=True)` is how the runner and the package fetcher cleaned up,
and on Windows it quietly did not: git marks its object files read-only, Windows refuses to
delete a read-only file, and `ignore_errors` turned the refusal into nothing. Every fix job left
its clone behind in the runner's work directory, and a long-running runner fills its disk one
repository at a time. The test that says "the workspace is removed" caught it on the Windows CI
leg; Linux and macOS delete read-only files in a writable directory and never showed it.
"""

from __future__ import annotations

import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


class Trees:
    """Directory trees this tool created and must leave nothing of."""

    @staticmethod
    def _writable_then_retry(function: Callable[[str], Any], path: str, _error: object) -> None:
        """A removal was refused: make the entry and its directory writable, then try once more.

        Both, because the refusal comes from either side: Windows refuses to delete a read-only
        FILE, POSIX refuses to unlink anything from a read-only DIRECTORY.
        """
        try:
            entry = Path(path)
            for target in (entry, entry.parent):
                target.chmod(target.stat().st_mode | stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            function(path)
        except OSError:
            # Still refused (held open by another process, a vanished parent). Best effort: the
            # caller is cleaning up after itself and must not fail the job it just finished.
            pass

    @staticmethod
    def remove(path: Path | str) -> None:
        """Delete `path` and everything under it, read-only files included. Never raises."""
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=Trees._writable_then_retry)
            else:  # pragma: no cover - 3.11 only
                shutil.rmtree(path, onerror=Trees._writable_then_retry)
        except FileNotFoundError:
            pass
        except OSError:
            pass


__all__ = ["Trees"]
