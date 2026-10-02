"""Tell someone when a scan fails its gate: a signed webhook, Slack or Microsoft Teams.

A security tool nobody hears from gets uninstalled, so the CLI can post one message per scan when
the gate fails. The rules, each of which is a way this could otherwise go wrong:

* **Destinations come only from the environment.** `CORDON_NOTIFY_SLACK`, `CORDON_NOTIFY_TEAMS`
  and `CORDON_NOTIFY_WEBHOOK`. A Slack or Teams incoming-webhook URL is a credential, and a URL on
  the command line leaks into process listings and CI logs. The command line names channels only
  (`--notify slack,teams,webhook`).
* **Notifying never changes the scan.** A failed delivery is reported on stderr and the exit code
  stays the gate's. It is also a separate, explicit request: `--notify` does not make the scan
  itself use the network.
* **Nothing sensitive leaves.** A message carries rule ids, severities, locations and fingerprints.
  Never a finding's message or evidence, which can quote a masked secret or a line of source.
* **HTTPS only, no redirects, five seconds.** A redirect could turn an https destination into an
  http one, so none is followed.

The generic webhook uses the Cordon event contract (`schemas/cordon-event-v1.schema.json`), the
same envelope and signature Cordon Cloud sends: headers `X-Cordon-Event`, `X-Cordon-Delivery`
(an idempotency key) and `X-Cordon-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">`
keyed by `CORDON_NOTIFY_WEBHOOK_SECRET`. A webhook without a secret is refused rather than sent
unsigned, because a receiver could not tell it from a forgery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cordon_scanner.core.models import Finding, ScanResult, Severity
from cordon_scanner.version import __version__

CHANNELS: Final = ("webhook", "slack", "teams")
"""Every channel `--notify` accepts, in the order they are sent."""

ENVIRONMENT: Final = {
    "webhook": "CORDON_NOTIFY_WEBHOOK",
    "slack": "CORDON_NOTIFY_SLACK",
    "teams": "CORDON_NOTIFY_TEAMS",
}
SECRET_VARIABLE: Final = "CORDON_NOTIFY_WEBHOOK_SECRET"  # noqa: S105 - a variable name

EVENT_SCHEMA: Final = "cordon.event/v1"
EVENT_TYPE: Final = "scan.completed"

TIMEOUT_SECONDS: Final = 5.0
MAX_LISTED: Final = 10
"""Findings named in one message. The rest are counted, never listed."""

USER_AGENT: Final = f"cordon-scanner/{__version__} (+https://github.com/Threx-code/cordon)"

Transport = Callable[[str, bytes, Mapping[str, str]], int]
"""Posts a body and returns the HTTP status. Replaced in tests; the default is `_post`."""


@dataclass(frozen=True)
class Delivery:
    """What happened to one channel. `error` is safe to print: it never contains the URL."""

    channel: str
    ok: bool
    error: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Webhooks:
    """Signed webhook delivery, and its receiver-side check."""

    @staticmethod
    def _post(url: str, body: bytes, headers: Mapping[str, str]) -> int:
        request = urllib.request.Request(  # noqa: S310  (scheme checked by the caller)
            url, data=body, headers=dict(headers), method="POST"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)

    @staticmethod
    def signature(secret: str, timestamp: int, body: bytes) -> str:
        """The `X-Cordon-Signature` value: `t=<timestamp>,v1=<hex HMAC-SHA256 of "t.body">`."""
        mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
        return f"t={timestamp},v1={mac.hexdigest()}"

    @staticmethod
    def verify(secret: str, header: str, body: bytes, *, now: float, tolerance: int = 300) -> bool:
        """Receiver-side check, shipped so a receiver can use the reference implementation.

        Rejects a signature older than `tolerance` seconds (five minutes, as the contract states),
        which is what stops a captured delivery from being replayed later.
        """
        parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
        try:
            timestamp = int(parts["t"])
        except (KeyError, ValueError):
            return False
        if abs(now - timestamp) > tolerance:
            return False
        expected = Webhooks.signature(secret, timestamp, body).split("v1=", 1)[1]
        return hmac.compare_digest(expected, parts.get("v1", ""))

    @staticmethod
    def _safe(finding: Finding) -> dict[str, Any]:
        location = finding.location.package or finding.location.path
        if finding.location.line and not finding.location.package:
            location = f"{location}:{finding.location.line}"
        return {
            "rule_id": finding.rule_id,
            "severity": str(finding.severity),
            "category": str(finding.category),
            "location": location,
            "fingerprint": finding.fingerprint,
        }

    @staticmethod
    def _target_name(result: ScanResult) -> str:
        """The repository's remote without credentials, or the target's last path segment."""
        repository = result.repository
        remote = (repository.remote if repository else None) or ""
        if remote:
            parsed = urllib.parse.urlsplit(remote)
            if parsed.scheme in ("http", "https", "ssh") and parsed.hostname:
                return f"{parsed.hostname}{parsed.path}".removesuffix(".git")
            if "@" in remote and ":" in remote:  # git@host:owner/repo.git
                return remote.split("@", 1)[1].replace(":", "/", 1).removesuffix(".git")
        root = ((repository.root if repository else None) or "").rstrip("/\\")
        return root.replace("\\", "/").rsplit("/", 1)[-1] or "scan"


class Notifier:
    """Builds and sends the gate-failure message to each requested channel."""

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._environ = os.environ if environ is None else environ
        self._transport = transport or Webhooks._post
        self._clock = clock

    @staticmethod
    def parse_channels(value: str) -> tuple[str, ...]:
        """`slack,teams` to `("slack", "teams")`, refusing a channel that does not exist."""
        requested = [part.strip().lower() for part in value.split(",") if part.strip()]
        unknown = sorted(set(requested) - set(CHANNELS))
        if unknown:
            raise ValueError(
                f"unknown notify channel(s): {', '.join(unknown)}; choose from {', '.join(CHANNELS)}"
            )
        return tuple(channel for channel in CHANNELS if channel in requested)

    def send(
        self, channels: Sequence[str], result: ScanResult, *, reason: str, exit_code: int
    ) -> list[Delivery]:
        """Send to each channel. Never raises: every failure is a `Delivery` with an error."""
        summary = Summary.of(result, reason=reason, exit_code=exit_code)
        deliveries: list[Delivery] = []
        for channel in channels:
            try:
                deliveries.append(self._send_one(channel, summary))
            except Exception as exc:  # a notifier must not take the scan down with it
                deliveries.append(Delivery(channel, False, type(exc).__name__))
        return deliveries

    def _send_one(self, channel: str, summary: Summary) -> Delivery:
        variable = ENVIRONMENT[channel]
        url = self._environ.get(variable, "").strip()
        if not url:
            return Delivery(channel, False, f"{variable} is not set")
        if urllib.parse.urlsplit(url).scheme != "https":
            return Delivery(channel, False, f"{variable} must be an https URL")

        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if channel == "webhook":
            secret = self._environ.get(SECRET_VARIABLE, "")
            if not secret:
                return Delivery(
                    channel, False, f"{SECRET_VARIABLE} is not set; refusing to send unsigned"
                )
            body, extra = self._signed_event(summary, secret)
            headers.update(extra)
        elif channel == "slack":
            body = json.dumps(summary.slack(), separators=(",", ":")).encode()
        else:
            body = json.dumps(summary.teams(), separators=(",", ":")).encode()

        try:
            status = self._transport(url, body, headers)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return Delivery(channel, False, f"{type(exc).__name__} delivering to {channel}")
        if not 200 <= status < 300:
            return Delivery(channel, False, f"HTTP {status} from {channel}")
        return Delivery(channel, True)

    def _signed_event(self, summary: Summary, secret: str) -> tuple[bytes, dict[str, str]]:
        now = int(self._clock())
        delivery = str(uuid.uuid4())
        body = json.dumps(
            summary.event(sequence=int(self._clock() * 1000)), sort_keys=True
        ).encode()
        return body, {
            "X-Cordon-Event": EVENT_TYPE,
            "X-Cordon-Delivery": delivery,
            "X-Cordon-Signature": Webhooks.signature(secret, now, body),
        }


@dataclass(frozen=True)
class Summary:
    """What a notification says about a scan. Built only from fields that are safe to send."""

    target: str
    revision: str
    reason: str
    exit_code: int
    complete: bool
    counts: dict[str, int]
    listed: tuple[dict[str, Any], ...]
    total: int

    @staticmethod
    def of(result: ScanResult, *, reason: str, exit_code: int) -> Summary:
        active = [f for f in result.findings if not f.is_suppressed]
        ordered = sorted(active, key=lambda f: (-int(f.severity), f.rule_id, f.location.path))
        counts = Counter(str(f.severity) for f in active)
        return Summary(
            target=Webhooks._target_name(result),
            revision=((result.repository.revision if result.repository else None) or "")[:12],
            reason=reason,
            exit_code=exit_code,
            complete=result.complete,
            counts={str(s): counts.get(str(s), 0) for s in sorted(Severity, reverse=True)},
            listed=tuple(Webhooks._safe(f) for f in ordered[:MAX_LISTED]),
            total=len(active),
        )

    def headline(self) -> str:
        worst = next((s for s, n in self.counts.items() if n), "info")
        return f"Cordon: {self.target} failed its gate ({worst.upper()})"

    def lines(self) -> list[str]:
        out = [f"{f['severity'].upper()} {f['rule_id']} at {f['location']}" for f in self.listed]
        if self.total > len(self.listed):
            out.append(f"... and {self.total - len(self.listed)} more")
        return out

    def event(self, *, sequence: int) -> dict[str, Any]:
        return {
            "schema": EVENT_SCHEMA,
            "type": EVENT_TYPE,
            "sequence": sequence,
            "source": "cli",
            "scan": {
                "target": self.target,
                "revision": self.revision,
                "gate": "failed",
                "reason": self.reason,
                "exit_code": self.exit_code,
                "complete": self.complete,
                "counts": self.counts,
                "findings": list(self.listed),
                "total_findings": self.total,
                "engine_version": __version__,
            },
        }

    def slack(self) -> dict[str, Any]:
        detail = "\n".join(self.lines()) or "No findings listed."
        return {
            "text": self.headline(),
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": self.headline()[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why:* {self.reason}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{detail}```"}},
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": self._context()}],
                },
            ],
        }

    def teams(self) -> dict[str, Any]:
        # An Adaptive Card inside a message: the shape both Teams Workflows webhooks and the
        # older incoming-webhook connector accept.
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": self.headline()},
            {"type": "TextBlock", "wrap": True, "text": f"Why: {self.reason}"},
        ]
        body += [
            {"type": "TextBlock", "wrap": True, "fontType": "Monospace", "text": line}
            for line in self.lines()
        ]
        body.append({"type": "TextBlock", "isSubtle": True, "wrap": True, "text": self._context()})
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

    def _context(self) -> str:
        counts = ", ".join(f"{n} {s}" for s, n in self.counts.items() if n) or "no findings"
        revision = f" @ {self.revision}" if self.revision else ""
        partial = "" if self.complete else " · scan INCOMPLETE"
        return f"{counts}{partial} · {self.target}{revision} · cordon-scanner {__version__}"


__all__ = ["CHANNELS", "Delivery", "Notifier", "Summary", "Webhooks"]
