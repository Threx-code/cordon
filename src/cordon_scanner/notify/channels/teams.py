"""Microsoft Teams (`CORDON_NOTIFY_TEAMS`), as an Adaptive Card inside a message: the shape both
Teams Workflows webhooks and the older incoming-webhook connector accept."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cordon_scanner.notify.channel import Message

if TYPE_CHECKING:
    from cordon_scanner.notify.channel import Occasion
    from cordon_scanner.notify.summary import Summary


class TeamsChannel:
    """A Teams Workflows (or connector) webhook."""

    id = "teams"
    variable = "CORDON_NOTIFY_TEAMS"

    def message(self, summary: Summary, occasion: Occasion) -> Message:
        return Message(json.dumps(self.card(summary), separators=(",", ":")).encode())

    @staticmethod
    def card(summary: Summary) -> dict[str, Any]:
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": summary.headline()},
            {"type": "TextBlock", "wrap": True, "text": f"Why: {summary.reason}"},
        ]
        body += [
            {"type": "TextBlock", "wrap": True, "fontType": "Monospace", "text": line}
            for line in summary.lines()
        ]
        body.append(
            {"type": "TextBlock", "isSubtle": True, "wrap": True, "text": summary.context()}
        )
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }


__all__ = ["TeamsChannel"]
