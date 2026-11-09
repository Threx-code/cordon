"""Clean verdicts remembered by hash, so the second `cordon npm install` of the same tree is quick.

Only *clean* verdicts are kept, and only for a day: a blocked file is scanned and reported every time,
and an entry expires so a new intel record or rule reaches files scanned before it existed. The key is
the file's registry hash with the scanner's version and the policy the scan ran under, so a stricter
`--cordon-fail-on` or an upgrade never reuses a verdict it did not produce. Entries are empty files in a
0700 directory: the name is the record, the modification time its age. A cache that cannot be read or
written is no cache, never an error -- the files are simply scanned.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar


@dataclass(frozen=True)
class VerdictCache:
    root: Path | None
    #: Scanner version and policy: part of every key.
    identity: str

    TTL_SECONDS: ClassVar[int] = 24 * 3600

    @classmethod
    def default(cls, identity: str) -> VerdictCache:
        """`$CORDON_CACHE_DIR/install-verdicts`, else the platform's user cache directory.
        `CORDON_INSTALL_CACHE=0` turns it off."""
        if os.environ.get("CORDON_INSTALL_CACHE", "1") == "0":
            return cls(None, identity)
        base = os.environ.get("CORDON_CACHE_DIR") or os.environ.get("XDG_CACHE_HOME")
        root = Path(base) if base else Path.home() / ".cache"
        if not os.environ.get("CORDON_CACHE_DIR"):
            root = root / "cordon"
        return cls(root / "install-verdicts", identity)

    def _entry(self, key: str) -> Path | None:
        if self.root is None:
            return None
        name = hashlib.sha256(f"{self.identity}\0{key}".encode()).hexdigest()
        return self.root / name[:2] / name

    def clean(self, key: str, now: float | None = None) -> bool:
        """A fresh clean verdict for these bytes under this scanner and policy."""
        entry = self._entry(key)
        if entry is None:
            return False
        try:
            age = (now if now is not None else time.time()) - entry.stat().st_mtime
        except OSError:
            return False
        return 0 <= age < self.TTL_SECONDS

    def remember(self, keys: list[str]) -> None:
        for key in keys:
            entry = self._entry(key)
            if entry is None:
                return
            try:
                entry.parent.parent.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
                entry.parent.mkdir(mode=stat.S_IRWXU, exist_ok=True)
                entry.touch(mode=0o600)
                os.utime(entry)
            except OSError:
                return


__all__ = ["VerdictCache"]
