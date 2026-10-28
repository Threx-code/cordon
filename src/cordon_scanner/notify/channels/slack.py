"""Slack, through an incoming webhook (`CORDON_NOTIFY_SLACK`), as a Block Kit message."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.notify.channel import Message

if TYPE_CHECKING:
    from cordon_scanner.notify.channel import Occasion
    from cordon_scanner.notify.summary import Summary


class SlackChannel:
    """A Slack incoming webhook."""

    id = "slack"
    variable = "CORDON_NOTIFY_SLACK"
    HEADER_LIMIT: Final = 150
    """Slack refuses a header block longer than this."""

    def message(self, summary: Summary, occasion: Occasion) -> Message:
        return Message(json.dumps(self.blocks(summary), separators=(",", ":")).encode())

    def blocks(self, summary: Summary) -> dict[str, Any]:
        detail = "\n".join(summary.lines()) or "No findings listed."
        headline = summary.headline()
        return {
            "text": headline,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": headline[: self.HEADER_LIMIT]},
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why:* {summary.reason}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{detail}```"}},
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": summary.context()}],
                },
            ],
        }


__all__ = ["SlackChannel"]
