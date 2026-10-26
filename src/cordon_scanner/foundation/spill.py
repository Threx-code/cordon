"""Where an archive member too large to hold in memory is kept while it is scanned: on disk.

A member past `Limits.max_file_bytes` used to be held whole in memory, and past the member limit
refused unread: twelve workers each holding a package's 60 MB members is how a scan runs out of
memory, and a refused member is where a payload padded past the limit goes unread. A member past
`max_file_bytes` is written here instead, a chunk at a time, and read back the way a large file on
disk is read -- every rule its first `max_file_bytes`, the sweeps and the code features every
window -- so memory holds a prefix per member whatever the archive holds.

What the archive reader's in-memory design guarded against still holds. Each process writes to
its own directory, made by `tempfile.mkdtemp` (mode 0700: no other user lists or opens it), and
each file is 0600 and never executable; nothing is extracted under its own name, so no member name
can steer where a write lands or what it overwrites. A file is removed when the content read from
it is released, the directory when the process exits, and a directory a crashed process left is
removed by the next process that spills.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, ClassVar


class SpilledBytes(bytes):
    """A member kept on disk: as bytes, its first `max_file_bytes` -- what every rule reads, as of a
    large file -- and, at `path`, all `size` bytes of it."""

    path: str
    size: int
    owner: int

    def __new__(cls, prefix: bytes, path: str, size: int) -> SpilledBytes:
        spilled = super().__new__(cls, prefix)
        spilled.path, spilled.size, spilled.owner = path, size, os.getpid()
        return spilled

    def __del__(self) -> None:
        # Only by the process that wrote it: a forked worker holding a copy of this object must
        # not remove the file its parent is still scanning.
        if getattr(self, "owner", None) == os.getpid():
            Spill.remove(self.path)

    def read_whole(self) -> bytes:
        """All of it, in memory: only for a caller bounded by its own limit (a nested archive)."""
        return Path(self.path).read_bytes()


class Spill:
    """The process's spill directory and the files in it."""

    PREFIX: ClassVar[str] = "cordon-spill-"
    _lock: ClassVar[threading.Lock] = threading.Lock()
    _directory: ClassVar[str | None] = None

    @staticmethod
    def directory() -> str:
        with Spill._lock:
            if Spill._directory is None or not Path(Spill._directory).is_dir():
                Spill.sweep()
                Spill._directory = tempfile.mkdtemp(prefix=f"{Spill.PREFIX}{os.getpid()}-")
                atexit.register(Spill._clear, Spill._directory, os.getpid())
            return Spill._directory

    @staticmethod
    def _clear(directory: str, owner: int) -> None:
        if os.getpid() == owner:
            shutil.rmtree(directory, ignore_errors=True)

    @staticmethod
    def writer() -> tuple[BinaryIO, str]:
        """A new spill file, open for writing, and its path."""
        descriptor, path = tempfile.mkstemp(dir=Spill.directory(), suffix=".member")
        return os.fdopen(descriptor, "wb"), path

    @staticmethod
    def remove(path: str) -> None:
        with contextlib.suppress(OSError):
            Path(path).unlink()

    @staticmethod
    def sweep() -> None:
        """Remove the spill directories of processes that are no longer running."""
        root = Path(tempfile.gettempdir())
        for entry in root.glob(f"{Spill.PREFIX}*"):
            pid = entry.name[len(Spill.PREFIX) :].split("-", 1)[0]
            if pid.isdigit() and int(pid) != os.getpid() and not Spill._running(int(pid)):
                shutil.rmtree(entry, ignore_errors=True)

    @staticmethod
    def _running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:  # it exists and is another user's: not ours to remove
            return True
        return True


__all__ = ["Spill", "SpilledBytes"]
