"""The Cordon event contract, `cordon.event/v1`: the envelope a webhook carries, and its signature.

Cordon Cloud sends the same envelope with the same signature, so one receiver serves both. The
signature is `X-Cordon-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">`. `verify` is
the receiver's side, shipped as the reference implementation: it refuses a signature older than five
minutes, which is what stops a captured delivery from being replayed later, and it accepts any of
several secrets, so a receiver can take the old and the new one while a secret is being changed.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence


class EventEnvelope:
    """The envelope's fixed names."""

    SCHEMA: Final = "cordon.event/v1"
    SCAN_COMPLETED: Final = "scan.completed"
    EVENT_HEADER: Final = "X-Cordon-Event"
    DELIVERY_HEADER: Final = "X-Cordon-Delivery"
    SIGNATURE_HEADER: Final = "X-Cordon-Signature"


class EventSignature:
    """Signing a delivery, and checking one."""

    TOLERANCE_SECONDS: Final = 300

    @staticmethod
    def sign(secret: str, timestamp: int, body: bytes) -> str:
        """The `X-Cordon-Signature` value: `t=<timestamp>,v1=<hex HMAC-SHA256 of "t.body">`."""
        mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
        return f"t={timestamp},v1={mac.hexdigest()}"

    @staticmethod
    def verify(
        secrets: str | Sequence[str],
        header: str,
        body: bytes,
        *,
        now: float,
        tolerance: int = TOLERANCE_SECONDS,
    ) -> bool:
        """Whether `header` signs `body` with one of `secrets`, within `tolerance` seconds of `now`."""
        parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
        try:
            timestamp = int(parts["t"])
        except (KeyError, ValueError):
            return False
        if abs(now - timestamp) > tolerance:
            return False
        given = parts.get("v1", "")
        keys = (secrets,) if isinstance(secrets, str) else tuple(secrets)
        matched = False
        for secret in keys:
            expected = EventSignature.sign(secret, timestamp, body).split("v1=", 1)[1]
            # Every key is compared, so the time taken does not say which one matched.
            matched = hmac.compare_digest(expected, given) or matched
        return matched


__all__ = ["EventEnvelope", "EventSignature"]
