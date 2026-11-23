"""How well the agent collected: `complete`, or `degraded` with one reason from a closed list.

An agent whose decision bundle has expired, whose policy is unavailable or whose signing key has expired keeps collecting and
says so in its report: `collection: {status: degraded, reason: bundle_expired | policy_unavailable | key_expired}`, and
`{status: complete}` once fixed. The three reasons are listed once here; the platform's own list is held in
`tests/unit/data/collection/accepted.json`, which a test compares with this one so the two cannot drift.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Final

STATUS_KEY: Final = "collection"
STORE_FOLDER: Final = "device"
"""The device runtime's local store (`cloud/local_store.py`) lives in this folder of the config directory (`CloudAuth.config_dir`, `CORDON_CONFIG_DIR` when set): one place for a device's state. A device with no such folder holds no policy of Cordon's, and its collection is not degraded by one."""


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
    def reason(cls) -> str | None:
        """Why the collection is degraded now, or None: the device credential first (`key_expired`), then the policy bundle store (`of_store`)."""
        return cls.of_credential() or cls.of_store()

    @classmethod
    def of_credential(cls) -> str | None:
        """`key_expired` when the device holds a stored sign-in whose access token is past its not-after and cannot be refreshed (no refresh token); None with no stored sign-in (a device that reports with its MDM token holds no credential with an expiry) or one that is current or renewable."""
        from cordon_scanner.cloud.auth import CloudAuth

        credentials = CloudAuth.load()
        if credentials is None or credentials.refresh_token:
            return None
        return "key_expired" if credentials.expired(cls.now().timestamp()) else None

    @classmethod
    def of_store(cls, root: Path | None = None) -> str | None:
        """Why the collection is degraded now, read from the store the device runtime keeps (`STORE_FOLDER` of the config directory), or None: no store set, or a store holding a bundle that has not expired. A store with no bundle is `policy_unavailable`; one whose newest bundle is past its `expires_at` is `bundle_expired`. A signing key past its window is told by `LocalRuntime.collection_reason`, which holds the delegation this cannot read."""
        from cordon_scanner.cloud.auth import CloudAuth
        from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError
        from cordon_scanner.cloud.local_store import LocalStore

        if root is None:
            root = CloudAuth.config_dir() / STORE_FOLDER
            if not (root / "bundle").is_dir():
                return None
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
