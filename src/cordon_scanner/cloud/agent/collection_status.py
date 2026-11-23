"""How well the agent collected: `complete`, or `degraded` with one reason from a closed list.

An agent whose decision bundle has expired, whose policy is unavailable or whose signing key has expired keeps collecting and
says so in its report: `collection: {status: degraded, reason: bundle_expired | policy_unavailable | key_expired}`, and
`{status: complete}` once fixed. The three reasons are listed once here; the platform's own list is held in
`tests/unit/data/collection/accepted.json`, which a test compares with this one so the two cannot drift.
"""

from __future__ import annotations

from typing import ClassVar, Final

STATUS_KEY: Final = "collection"


class CollectionStatus:
    REASONS: ClassVar[tuple[str, ...]] = ("bundle_expired", "policy_unavailable", "key_expired")

    @classmethod
    def payload(cls, reason: str | None) -> dict[str, str]:
        """The `collection` object of a report: complete for no reason, degraded with the reason otherwise; `ValueError` for a reason
        that is not on the list (a degraded collection never carries words the agent wrote)."""
        if reason is None:
            return {"status": "complete"}
        if reason not in cls.REASONS:
            raise ValueError(
                f"a degraded collection gives one reason of {', '.join(cls.REASONS)}, not {reason!r}"
            )
        return {"status": "degraded", "reason": reason}


__all__ = ["STATUS_KEY", "CollectionStatus"]
