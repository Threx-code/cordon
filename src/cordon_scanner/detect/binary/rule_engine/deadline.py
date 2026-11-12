"""The time one match may take, measured in the matching thread's CPU time.

A wall-clock budget made a file's result depend on the machine's load: the same file timed out
(`OPERATIONAL.FILE.TIMEOUT`, a blocking gap, exit 4) on a busy machine and matched on an idle one.
The budget is the CPU the matching thread uses, which a file costs the same whatever else runs, with
a wall backstop at `BACKSTOP` times it for a match that stalls without using CPU (the supervisor's
own shape, `engine/isolation/supervisor.Bounds`). Either ends the match; neither passes the file.

Matching is synchronous in the calling thread (`RuleFile.match` -> `Rules.match`) and, for a large
file, in the pool worker's one thread (`RulePool`), so the thread whose CPU is read is the one that
matches. A plain float is still a `time.monotonic()` deadline, the meaning it had.
"""

from __future__ import annotations

import time
from typing import ClassVar

MESSAGE = "matching took longer than the time allowed"


class MatchStalled(TimeoutError):
    """The wall backstop ended the match while its CPU budget was not used up: the match was starved
    or blocked, not slow. The caller may run it once more; the CPU budget's timeout is final."""


class MatchDeadline:
    """`seconds` of the calling thread's CPU time, and `BACKSTOP` times that of wall time."""

    BACKSTOP: ClassVar[float] = 10.0

    __slots__ = ("cpu_end", "wall_end")

    def __init__(self, seconds: float) -> None:
        self.cpu_end = time.thread_time() + seconds
        self.wall_end = time.monotonic() + seconds * MatchDeadline.BACKSTOP

    def cpu_spent(self) -> bool:
        return time.thread_time() > self.cpu_end

    def wall_spent(self) -> bool:
        return time.monotonic() > self.wall_end

    @staticmethod
    def passed(deadline: Until) -> bool:
        """Whether `deadline` (None: never; a float: a `time.monotonic()` reading) has passed."""
        if deadline is None:
            return False
        if isinstance(deadline, MatchDeadline):
            return deadline.cpu_spent() or deadline.wall_spent()
        return time.monotonic() > deadline

    @staticmethod
    def timeout(deadline: Until) -> TimeoutError:
        """The error for a deadline that has passed: `MatchStalled` when only the wall backstop ran out."""
        if isinstance(deadline, MatchDeadline) and not deadline.cpu_spent():
            return MatchStalled(MESSAGE)
        return TimeoutError(MESSAGE)

    @staticmethod
    def left(deadline: Until) -> float:
        """Seconds a native call may take: -1.0 for no deadline. A native call is timed by the wall
        clock in C, so it is given what is left of the wall backstop, never of the CPU budget (which
        it would spend faster on a loaded machine); the CPU budget is read between native calls."""
        if deadline is None:
            return -1.0
        if isinstance(deadline, MatchDeadline):
            return max(deadline.wall_end - time.monotonic(), 0.0)
        return max(deadline - time.monotonic(), 0.0)


Until = float | MatchDeadline | None
"""What a search is given as its time limit."""
