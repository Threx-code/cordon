"""Ordinary build notification.

Posts to a chat webhook, which is what webhooks are for. The difference from
the malicious sample is what it sends: a message it composed, not the
environment it was given.
"""

import json
import urllib.request

WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"


def announce(version: str, status: str) -> None:
    body = json.dumps({"text": f"build {version} finished: {status}"}).encode()
    request = urllib.request.Request(
        WEBHOOK, data=body, headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(request, timeout=10)
