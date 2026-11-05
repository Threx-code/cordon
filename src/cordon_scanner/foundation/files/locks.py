"""An exclusive, non-blocking lock on an open file, on every platform.

The copy budget's slots and the spill directory's liveness lock were `fcntl.flock`, which Windows has
not, so on Windows there was no copy budget at all: several workers could each copy a whole binary
member at once, the memory bound the budget exists for (4 Nov, the first full Windows run). Windows
locks a byte range with `msvcrt.locking` instead, and, like `flock`, frees it when the process that
held it ends, which is the liveness both callers rely on.

```
   FileLocks.take(fd)     True: held now; False: another process holds it (never waits)
   FileLocks.release(fd)  unlocked; the caller closes the descriptor after
   FileLocks.available()  False only on a platform with neither (no budget, no liveness: as before)
```
"""

from __future__ import annotations

import importlib
import os
from types import ModuleType


class FileLocks:
    """Byte 0 of a file, locked exclusively without waiting: `flock` on POSIX, `msvcrt` on Windows."""

    @staticmethod
    def _module(name: str) -> ModuleType | None:
        try:
            return importlib.import_module(name)
        except ImportError:
            return None

    @staticmethod
    def available() -> bool:
        return FileLocks._module("fcntl") is not None or FileLocks._module("msvcrt") is not None

    @staticmethod
    def take(fd: int) -> bool:
        fcntl = FileLocks._module("fcntl")
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            return True
        msvcrt = FileLocks._module("msvcrt")
        if msvcrt is None:
            return True  # nothing to lock with: every caller treats this as "no bound", as before
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    @staticmethod
    def release(fd: int) -> None:
        fcntl = FileLocks._module("fcntl")
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            return
        msvcrt = FileLocks._module("msvcrt")
        if msvcrt is not None:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass  # not held: closing the descriptor frees whatever is left


__all__ = ["FileLocks"]
