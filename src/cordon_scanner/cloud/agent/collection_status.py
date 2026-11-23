"""How well the agent collected: `complete`, or `degraded` with one reason from a closed list.

An agent whose decision bundle has expired, whose policy is unavailable or whose signing key has expired keeps collecting and
says so in its report: `collection: {status: degraded, reason: bundle_expired | policy_unavailable | key_expired}`, and
`{status: complete}` once fixed. The three reasons are listed once here; the platform's own list is held in
`tests/unit/data/collection/accepted.json`, which a test compares with this one so the two cannot drift.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Final

STATUS_KEY: Final = "collection"
STORE_ENV: Final = "CORDON_DEVICE_STORE"
"""The directory of the device runtime's local store (`cloud/local_store.py`). With none set the device holds no policy of Cordon's, and its collection is not degraded by one."""


class CollectionStatus:
    now: ClassVar[Callable[[], datetime]] = staticmethod(lambda: datetime.now(UTC))
    """The clock the report reads; a test replaces it."""

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

    @classmethod
    def of_store(cls, root: Path | None = None) -> str | None:
        """Why the collection is degraded now, read from the store the device runtime keeps (`CORDON_DEVICE_STORE`), or None: no store set, or a store holding a bundle that has not expired. A store with no bundle is `policy_unavailable`; one whose newest bundle is past its `expires_at` is `bundle_expired`. A signing key past its window is told by `LocalRuntime.collection_reason`, which holds the delegation this cannot read."""
        from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError
        from cordon_scanner.cloud.local_store import LocalStore

        if root is None:
            kept = os.environ.get(STORE_ENV)
            if not kept:
                return None
            root = Path(kept)
        envelopes = LocalStore(root).load_bundle()
        if not envelopes:
            return "policy_unavailable"
        try:
            expires = datetime.fromisoformat(
                str(BundleChain.unverified_payload_document(envelopes[-1])["expires_at"])
            )
        except (BundleError, KeyError, ValueError):
            return "policy_unavailable"
        return "bundle_expired" if cls.now() > expires else None


__all__ = ["STATUS_KEY", "CollectionStatus"]
