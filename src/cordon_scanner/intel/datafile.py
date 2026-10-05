"""Small intel data files: the bundled copy, unless the user sync directory holds a newer one.

The same rule the advisory database follows, for the lists that are not advisories: removed editor
extensions, agent-action fixes. A bundled file that fails its digest is not used, and a synced copy
wins only when its `generated` stamp is newer, so neither a stale sync nor an edited wheel can
replace current data.
"""

from __future__ import annotations

import contextlib
import json
from functools import cache
from typing import Any

from cordon_scanner.intel.advisories import DATA_DIR, AdvisoryFiles


class IntelDataFile:
    """Small intel files: the bundled copy, unless a synced one is newer."""

    @staticmethod
    def _read(path: Any) -> dict[str, Any] | None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return document if isinstance(document, dict) else None

    @staticmethod
    @cache
    def newest(name: str) -> dict[str, Any]:
        """The newest trustworthy copy of `name`, or an empty document when there is none."""
        candidates: list[dict[str, Any]] = []
        with contextlib.suppress(OSError):
            trusted = AdvisoryFiles.trusted_user_file(name)
            synced = IntelDataFile._read(trusted) if trusted is not None else None
            if synced is not None:
                candidates.append(synced)
        if name not in AdvisoryFiles.tampered_files():
            bundled = IntelDataFile._read(DATA_DIR / name)
            if bundled is not None:
                candidates.append(bundled)
        return max(candidates, key=lambda d: str(d.get("generated", ""))) if candidates else {}

    @staticmethod
    def reset_cache() -> None:
        IntelDataFile.newest.cache_clear()


__all__ = ["IntelDataFile"]
