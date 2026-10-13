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
from pathlib import Path


class AtomicFile:
    @staticmethod
    def write(path: Path, data: bytes | str) -> Path:
        """Replace `path` with `data`, staged in its own directory, readable by its owner only."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        handle, staging = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(payload)
            Path(staging).replace(path)
        except BaseException:
            Path(staging).unlink(missing_ok=True)
            raise
        return path
