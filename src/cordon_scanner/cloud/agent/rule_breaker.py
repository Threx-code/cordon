"""The device's circuit breaker for delivered rules: a rule that blocks too many local scans is run as a warning.

The device runtime records, for every scan it decides, how many scans there were in the hour and which delivered rules blocked. The record is 24 hourly buckets in the runtime's own local store
(there is no other state: a one-shot command line scan keeps none and reports its per-scan counts only). A rule that blocked more than 1% of the scans of the last 24 hours, with at least
`MIN_SCANS` of them, is returned by `demotions` with the reason, and the caller hands those to `FeedPacks.packs(demote=...)`, which runs them as warnings. The reason is kept in the store too.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Final

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.cloud.local_store import LocalStore

KIND: Final = "breaker"
BUCKETS: Final = "buckets"
REASONS: Final = "reasons"


class RuleBreaker:
    HOURS: ClassVar[int] = 24
    THRESHOLD: ClassVar[float] = 0.01
    MIN_SCANS: ClassVar[int] = 100
    """Fewer scans than this in the window is too few to call a rate: one block of ten scans is not 10%."""

    def __init__(self, store: LocalStore) -> None:
        self._store = store

    @staticmethod
    def hour(clock: datetime) -> int:
        return int(clock.timestamp() // 3600)

    def _read(self, name: str) -> dict[str, Any]:
        blob = self._store.blob(KIND, name)
        try:
            found = json.loads(blob.data) if blob is not None else {}
        except ValueError:
            return {}
        return found if isinstance(found, dict) else {}

    def _write(self, name: str, document: dict[str, Any], clock: datetime) -> None:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        self._store.put_blob(KIND, name, body, clock.isoformat())

    def record(self, clock: datetime, blocked_rules: Iterable[str]) -> None:
        """One scan decided at `clock`, and the delivered rules that blocked it; buckets older than the window are dropped."""
        now = self.hour(clock)
        hours = {
            h: v
            for h, v in self._read(BUCKETS).items()
            if h.isdigit() and now - int(h) < self.HOURS
        }
        bucket = hours.setdefault(str(now), {"scans": 0, "blocked": {}})
        bucket["scans"] += 1
        for rule_id in set(blocked_rules):
            bucket["blocked"][rule_id] = bucket["blocked"].get(rule_id, 0) + 1
        self._write(BUCKETS, hours, clock)

    def demotions(self, clock: datetime) -> dict[str, str]:
        """The rules to run as warnings now, by id with the reason, and the reasons kept in the store."""
        now = self.hour(clock)
        scans = 0
        blocked: dict[str, int] = {}
        for hour, bucket in self._read(BUCKETS).items():
            if (
                not hour.isdigit()
                or not 0 <= now - int(hour) < self.HOURS
                or not isinstance(bucket, dict)
            ):
                continue
            scans += int(bucket.get("scans", 0))
            for rule_id, count in (bucket.get("blocked") or {}).items():
                blocked[rule_id] = blocked.get(rule_id, 0) + int(count)
        if scans < self.MIN_SCANS:
            return {}
        reasons = {
            rule_id: f"it blocked {count} of {scans} local scans in {self.HOURS} hours ({count / scans:.1%}), over {self.THRESHOLD:.0%}"
            for rule_id, count in sorted(blocked.items())
            if count / scans > self.THRESHOLD
        }
        if reasons:
            self._write(REASONS, reasons, clock)
        return reasons


__all__ = ["RuleBreaker"]
