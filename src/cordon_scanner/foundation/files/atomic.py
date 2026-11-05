"""Replacing a file so that a reader sees the old content or the new, never part of either.

Every writer here once staged its content under a fixed name (`<file>.tmp`) and renamed it into
place. Two scans sharing a cache directory -- parallel CI jobs, `bench/` workers -- then wrote the
same staging file: one renamed it away and the other's `chmod` or rename failed with
`FileNotFoundError`, which stopped that scan (review 98). Staging under a name nobody else holds
removes the race; the rename itself is atomic on one filesystem.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path


class AtomicFile:
    #: How long a replace Windows refuses is retried. Windows denies a rename onto a file another
    #: process is renaming onto or has open at that moment ("Access is denied"); eight writers on
    #: one file failed that way (5 Nov). POSIX renames never fail so.
    WINDOWS_RETRY_SECONDS = 5.0
    #: Whether renames here are Windows': read on each replace, so a test can take that path.
    WINDOWS = os.name == "nt"

    @staticmethod
    def replace(staging: Path, path: Path) -> None:
        """`staging` renamed onto `path` atomically; on Windows, a refusal is retried briefly."""
        if not AtomicFile.WINDOWS:
            staging.replace(path)
            return
        deadline, pause = time.monotonic() + AtomicFile.WINDOWS_RETRY_SECONDS, 0.005
        while True:
            try:
                staging.replace(path)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(pause)
                pause = min(pause * 2, 0.1)

    @staticmethod
    def write(path: Path, data: bytes | str) -> Path:
        """Replace `path` with `data`, staged in its own directory, readable by its owner only."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        handle, staging = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(payload)
            AtomicFile.replace(Path(staging), path)
        except BaseException:
            Path(staging).unlink(missing_ok=True)
            raise
        return path
