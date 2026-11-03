"""The scan's budget for the binary readers' owned whole copies (notes/74 addendum, cordon-47's design (b)).

Each worker of a scan may copy a whole binary member for its readers (`whole_bytes.py`). Several at once
raised a pair's memory.peak from 2.94 GB to 5.21 GB, with no unit costing more alone. So every copy of
one scan, in every worker, holds slots of one budget first:

```
  hold(nbytes, deadline) ─► the gate (one acquirer at a time, so waiters queue and never deadlock)
        ─► ceil(nbytes / 1 MiB) free slots, each a flock'd file in the scan's budget directory
        ─► held: the copy is made and read; the slots unlock when the readers return
  a member larger than the budget takes every slot and reads alone
  a holder that dies frees its slots at once: the kernel drops its locks (same liveness as the spill sweep)
  waiting past the scan's deadline: refused, with its reason, so the readers read the prefix and say so
```

With no directory (a scan that set none up, or a platform without `flock`) there is no budget, and every copy is
made as before.
"""

from __future__ import annotations

import contextlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(slots=True)
class Held:
    """The outcome of a hold: truthy when the slots are held."""

    ok: bool
    reason: str = ""
    alone: bool = False
    fds: list[int] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


class CopyBudget:
    """One scan's copy budget, shared by every worker through its directory."""

    BYTES: ClassVar[int] = 256 << 20
    SLOT: ClassVar[int] = 1 << 20
    POLL: ClassVar[float] = 0.05
    GATE: ClassVar[str] = "gate"

    def __init__(self, directory: str | None) -> None:
        self.directory = directory

    @property
    def slots(self) -> int:
        return CopyBudget.BYTES // CopyBudget.SLOT

    @contextlib.contextmanager
    def hold(self, nbytes: int, deadline: float | None) -> Iterator[Held]:
        """Hold the slots `nbytes` needs (every slot for a member larger than the budget) until the block
        ends, or refuse at `deadline` (this process's monotonic clock; None waits for as long as it takes)."""
        try:
            import fcntl
        except ImportError:  # no flock here: no budget, as with no directory
            yield Held(True)
            return
        if self.directory is None:
            yield Held(True)
            return
        need = min(self.slots, max(1, -(-nbytes // CopyBudget.SLOT)))
        alone = nbytes > CopyBudget.BYTES
        held = Held(False, alone=alone)
        gate = self._open(CopyBudget.GATE)
        try:
            if not self._wait(gate, deadline, fcntl):
                held.reason = "the copy budget was held until the deadline (waiting to take slots)"
                yield held
                return
            try:
                held.fds = self._take(need, deadline, fcntl)
            finally:
                fcntl.flock(gate, fcntl.LOCK_UN)
            if len(held.fds) < need:
                self._release(held.fds)
                held.fds = []
                held.reason = "the copy budget was held until the deadline"
                yield held
                return
            held.ok = True
            try:
                yield held
            finally:
                self._release(held.fds)
                held.fds = []
        finally:
            os.close(gate)

    def _open(self, name: str) -> int:
        assert self.directory is not None  # noqa: S101 - checked in `hold`
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        return os.open(Path(self.directory) / name, flags, 0o600)

    @staticmethod
    def _wait(fd: int, deadline: float | None, fcntl: object) -> bool:
        """The exclusive lock on `fd`, polled until it is free or `deadline` passes."""
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                return True
            except OSError:
                if deadline is not None and time.monotonic() >= deadline:
                    return False
                time.sleep(CopyBudget.POLL)

    def _take(self, need: int, deadline: float | None, fcntl: object) -> list[int]:
        """`need` free slots, collected in order while the gate is held; fewer if `deadline` passes."""
        taken: list[int] = []
        held_slots: set[int] = set()
        while True:
            for slot in range(self.slots):
                if len(taken) >= need:
                    return taken
                if slot in held_slots:
                    continue
                fd = self._open(f"slot-{slot:03d}")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
                except OSError:
                    os.close(fd)
                    continue
                taken.append(fd)
                held_slots.add(slot)
            if len(taken) >= need:
                return taken
            if deadline is not None and time.monotonic() >= deadline:
                return taken
            time.sleep(CopyBudget.POLL)

    @staticmethod
    def _release(fds: list[int]) -> None:
        for fd in fds:
            os.close(fd)  # closing drops the flock


__all__ = ["CopyBudget", "Held"]
