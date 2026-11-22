"""What one scan may read in windows, summed over its files and its workers (`limits.max_stream_total_bytes`).

`limits.max_stream_bytes` bounds one file's windows; a scan of many oversized files is bounded by this. The
total is a file in the scan's budget directory (the directory the binary readers' copy budget uses), so every
worker of a scan charges one count:

```
  charge(directory, nbytes, ceiling) ─► lock the ledger (byte 0, polled; one charger at a time)
        ─► spent + nbytes <= ceiling: spent += nbytes, True      (taken)
        ─► past it: nothing taken, False                         (the file's windows are not read: a gap)
  a scan with no directory has no total (as the copy budget has none): the per-file bound still applies
  a ledger that cannot be read refuses: the safe answer to a bound that cannot be checked is "not read"
```

A refusal takes nothing, so a smaller file after it may still fit; which of two files that do not both
fit is the one refused depends on which worker charged first, and the scan is incomplete either way.
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.files.locks import FileLocks

if TYPE_CHECKING:
    from collections.abc import Iterator


class StreamBudget:
    """One scan's count of bytes read in windows."""

    LEDGER: ClassVar[str] = "stream-bytes"
    POLL: ClassVar[float] = 0.001
    WIDTH: ClassVar[int] = 8

    @staticmethod
    def charge(directory: str | None, nbytes: int, ceiling: int) -> bool:
        """Whether `nbytes` more may be read in windows within `ceiling`, taking them if so."""
        if directory is None or nbytes <= 0 or not FileLocks.available():
            return True
        with StreamBudget._ledger(directory) as fd:
            spent = StreamBudget._read(fd)
            if spent is None or spent + nbytes > ceiling:
                return False
            StreamBudget._write(fd, spent + nbytes)
            return True

    @staticmethod
    def spent(directory: str) -> int:
        """What the scan has read in windows so far."""
        with StreamBudget._ledger(directory) as fd:
            return StreamBudget._read(fd) or 0

    @staticmethod
    @contextlib.contextmanager
    def _ledger(directory: str) -> Iterator[int]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(Path(directory) / StreamBudget.LEDGER, flags, 0o600)
        try:
            while not FileLocks.take(fd):
                time.sleep(StreamBudget.POLL)
            try:
                yield fd
            finally:
                FileLocks.release(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _read(fd: int) -> int | None:
        """The ledger's total: 0 for a ledger not yet written, None for one that is not a total."""
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, StreamBudget.WIDTH + 1)
        if not data:
            return 0
        if len(data) != StreamBudget.WIDTH:
            return None
        return int.from_bytes(data, "big")

    @staticmethod
    def _write(fd: int, total: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, total.to_bytes(StreamBudget.WIDTH, "big"))


__all__ = ["StreamBudget"]
