"""Which feed serials this device has run scans on, told to the platform once each.

A scan that ran on a feed serial this device has not reported yet queues one record, `{"serial", "intel_serial"}` (digits up to
12, or `none`), and nothing else. The platform stamps the time it first hears of the serial; the scanner writes none. The queue
sends the record to `POST /v1/devices/feed-serials` as `{"sightings": [record]}` with the device token; one device reports a
serial pair once, however many scans ran on it.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.transport import CloudTransport

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from cordon_scanner.cloud.local_store import LocalStore, Pending
    from cordon_scanner.cloud.transport import Transport

KIND: Final = "feed-serial"
REPORTED: Final = "reported"
PATH: Final = "/v1/devices/feed-serials"


class FeedSerials:
    FIELDS: ClassVar[tuple[str, ...]] = ("serial", "intel_serial")
    KEEP: ClassVar[int] = 50
    """The serial pairs remembered as reported; older ones are forgotten and a resend is harmless."""

    @staticmethod
    def valid(value: object) -> bool:
        return isinstance(value, str) and (
            value == "none" or (value.isdigit() and len(value) <= 12)
        )

    @classmethod
    def record(cls, feed: Mapping[str, Any]) -> dict[str, str] | None:
        """The two serials of a scan's `feed`, or None when either is not a serial or `none`."""
        found = {name: feed.get(name) for name in cls.FIELDS}
        if not all(cls.valid(value) for value in found.values()):
            return None
        return {name: str(value) for name, value in found.items()}

    @classmethod
    def queue(cls, store: LocalStore, feed: Mapping[str, Any], clock: datetime) -> bool:
        """Queue the record when this pair has not been reported; whether one was queued."""
        record = cls.record(feed)
        if record is None:
            return False
        pair = f"{record['serial']}/{record['intel_serial']}"
        blob = store.blob(KIND, REPORTED)
        try:
            seen = list(json.loads(blob.data)) if blob is not None else []
        except ValueError:
            seen = []
        if pair in seen:
            return False
        if not store.enqueue(
            KIND, json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ):
            return False
        body = json.dumps([*seen, pair][-cls.KEEP :], separators=(",", ":")).encode()
        store.put_blob(KIND, REPORTED, body, clock.isoformat())
        return True

    @classmethod
    def send(
        cls,
        item: Pending,
        *,
        url: str | None = None,
        token: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        """Send one queued record; raises, leaving it queued, when the platform does not take it."""
        if item.kind != KIND:
            raise CloudError(f"not a feed serial upload: {item.kind}")
        record = cls.record(json.loads(item.body))
        if record is None:
            raise CloudError("the queued feed serial is not a serial")
        device_token = token or os.environ.get("CORDON_DEVICE_TOKEN", "")
        if not device_token:
            raise CloudError("CORDON_DEVICE_TOKEN is not set; the MDM profile supplies it")
        response = CloudTransport.request(
            "POST",
            f"{CloudEndpoint.base_url(url)}{PATH}",
            json_body={"sightings": [record]},
            token=device_token,
            transport=transport,
        )
        if response.status not in (200, 201, 202):
            raise CloudError(f"the feed serial was refused ({CloudTransport.error_text(response)})")


__all__ = ["KIND", "PATH", "FeedSerials"]
