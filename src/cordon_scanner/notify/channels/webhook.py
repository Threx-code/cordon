"""A generic webhook: the signed `cordon.event/v1` envelope, the same a receiver gets from Cordon Cloud.

Signed with `CORDON_NOTIFY_WEBHOOK_SECRET`, and refused without it: a receiver could not tell an
unsigned delivery from a forgery.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

from cordon_scanner.notify.channel import ChannelRefused, Message
from cordon_scanner.notify.events import EventEnvelope, EventSignature

if TYPE_CHECKING:
    from cordon_scanner.notify.channel import Occasion
    from cordon_scanner.notify.summary import Summary


class WebhookChannel:
    """The signed Cordon event, to any HTTPS receiver."""

    id = "webhook"
    variable = "CORDON_NOTIFY_WEBHOOK"
    SECRET_VARIABLE: Final = "CORDON_NOTIFY_WEBHOOK_SECRET"  # noqa: S105 - a variable name

    def message(self, summary: Summary, occasion: Occasion) -> Message:
        secret = occasion.environ.get(self.SECRET_VARIABLE, "")
        if not secret:
            raise ChannelRefused(f"{self.SECRET_VARIABLE} is not set; refusing to send unsigned")
        body = json.dumps(summary.event(sequence=occasion.sequence), sort_keys=True).encode()
        return Message(
            body,
            {
                EventEnvelope.EVENT_HEADER: EventEnvelope.SCAN_COMPLETED,
                EventEnvelope.DELIVERY_HEADER: occasion.delivery,
                EventEnvelope.SIGNATURE_HEADER: EventSignature.sign(secret, occasion.now, body),
            },
        )


__all__ = ["WebhookChannel"]
