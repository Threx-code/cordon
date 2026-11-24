"""The device report that waits for the network (BP-8-8): queued in the device's local store when it cannot be sent, sent first next run.

A report is queued when the send fails because the cloud could not be reached or answered 5xx. A 4xx is a refusal (a bad token, a
payload the cloud will not take) and is never queued: sending it again changes nothing. At the next run the queued report goes
first, oldest first, and only then the new one. A newer report for the same device replaces the one waiting, so the queue holds
the latest inventory of each device and never a backlog of stale ones; the store's own bound caps the rest.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.cloud import CloudEndpoint, CloudError
from cordon_scanner.cloud.transport import CloudTransport, Transport

if TYPE_CHECKING:
    from cordon_scanner.cloud.local_store import LocalStore, Pending


class Unreachable(CloudError):
    """The report could not be delivered for a reason that may pass: no network, or a 5xx."""


class ReportQueue:
    PREFIX: ClassVar[str] = "device-report-"
    QUEUED: ClassVar[str] = "queued"
    ACCEPTED: ClassVar[tuple[int, ...]] = (200, 201, 202)

    @classmethod
    def kind(cls, payload: dict[str, Any]) -> str:
        """The upload kind of this device's report: one per install, so a newer report finds the one it replaces."""
        return cls.PREFIX + str(payload.get("device", {}).get("install_id", "unknown")).lower()

    @classmethod
    def post(
        cls, payload: dict[str, Any], *, url: str | None, token: str, transport: Transport | None
    ) -> str:
        """Send one report. Returns the receipt; raises `Unreachable` when it may pass, `CloudError` when the cloud refused it."""
        seen: list[int] = []
        base = transport or CloudTransport._urllib

        def tracked(
            method: str, url: str, *, body: bytes | None, headers: dict[str, str]
        ) -> tuple[int, bytes]:
            status, raw = base(method, url, body=body, headers=headers)
            seen.append(status)
            return status, raw

        try:
            response = CloudTransport.request(
                "POST",
                f"{CloudEndpoint.base_url(url)}/v1/devices/inventory",
                json_body=payload,
                token=token,
                transport=tracked,
            )
        except CloudError as exc:
            if (
                not seen or seen[-1] >= 500
            ):  # no answer at all, or a server error whose body was not JSON
                raise Unreachable(str(exc)) from exc
            raise
        if response.status >= 500:
            raise Unreachable(
                f"the cloud answered {response.status} ({CloudTransport.error_text(response)})"
            )
        if response.status not in cls.ACCEPTED:
            raise CloudError(f"the inventory was refused ({CloudTransport.error_text(response)})")
        return str(response.body.get("receipt", ""))

    @classmethod
    def deliver(
        cls,
        payload: dict[str, Any],
        store: LocalStore,
        *,
        url: str | None,
        token: str,
        transport: Transport | None = None,
    ) -> str:
        """Send what is waiting, oldest first, then `payload`. Returns the receipt, or `QUEUED` when it is waiting for the network."""

        def send(item: Pending) -> None:
            try:
                cls.post(json.loads(item.body), url=url, token=token, transport=transport)
            except Unreachable:
                raise
            except CloudError:
                return  # refused: sending it again changes nothing, so it leaves the queue and the ones behind it go on

        if store.drain(send).left:
            cls.keep(payload, store)
            return cls.QUEUED
        try:
            return cls.post(payload, url=url, token=token, transport=transport)
        except Unreachable:
            cls.keep(payload, store)
            return cls.QUEUED

    @classmethod
    def keep(cls, payload: dict[str, Any], store: LocalStore) -> None:
        """Queue `payload`, replacing the report of the same device that is waiting."""
        kind = cls.kind(payload)
        for item in store.pending():
            if item.kind == kind:
                store.discard(item)
        store.enqueue(kind, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


__all__ = ["ReportQueue", "Unreachable"]
