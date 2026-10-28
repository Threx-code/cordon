"""Sending a scan's notification to every requested channel at once, and saying what happened.

`send` never raises and never changes the scan: each channel's outcome is a `Delivery`, which the
command line reports on stderr. Channels are sent in parallel, so three channels wait no longer than
the slowest. Each is tried up to `RetryPolicy.attempts` times under one delivery id, and all of them
together stop at `RetryPolicy.deadline`.
"""

from __future__ import annotations

import os
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from cordon_scanner.engine.registry import Registry
from cordon_scanner.notify.channel import ChannelRefused, Occasion
from cordon_scanner.notify.summary import Summary
from cordon_scanner.notify.transport import HttpsTransport, Reply, RetryPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from cordon_scanner.foundation.models import ScanResult
    from cordon_scanner.notify.channel import Channel, Message
    from cordon_scanner.notify.transport import Transport


@dataclass(frozen=True)
class Delivery:
    """What happened to one channel. `error` is safe to print: it never contains the URL."""

    channel: str
    ok: bool
    error: str = ""
    attempts: int = 0
    """Posts made: 0 when the channel was refused before any."""
    delivery: str = ""
    """The idempotency key the receiver saw, for matching our record to theirs."""


class Notifier:
    """Builds each channel's message and delivers it."""

    TRIGGERS: Final = ("failed", "incomplete", "passed")
    DEFAULT_TRIGGERS: Final = ("failed", "incomplete")

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], object] | None = None,
        policy: RetryPolicy | None = None,
        channels: Sequence[Channel] | None = None,
        allow_plugins: bool = False,
    ) -> None:
        self._environ = os.environ if environ is None else environ
        self._transport = transport or HttpsTransport.post
        self._clock = clock
        self._stop = threading.Event()
        self._sleep = sleep or self._stop.wait
        self._policy = policy or RetryPolicy()
        found = channels if channels is not None else Notifier.available(allow_plugins)
        self._channels = {channel.id: channel for channel in found}

    @staticmethod
    def available(allow_plugins: bool = False) -> tuple[Channel, ...]:
        """The registered channels, the built-in ones first in their fixed order."""
        return tuple(Registry(allow_third_party=allow_plugins).notifiers())

    @staticmethod
    def parse_channels(value: str, *, allow_plugins: bool = False) -> tuple[str, ...]:
        """`slack,teams` to `("slack", "teams")`, refusing a channel that does not exist."""
        known = [channel.id for channel in Notifier.available(allow_plugins)]
        return Notifier._parse(value, known, "notify channel")

    @staticmethod
    def parse_triggers(value: str) -> tuple[str, ...]:
        """`failed,passed` to `("failed", "passed")`, refusing an occasion that does not exist."""
        return Notifier._parse(value, list(Notifier.TRIGGERS), "notify trigger")

    @staticmethod
    def _parse(value: str, known: Sequence[str], what: str) -> tuple[str, ...]:
        requested = [part.strip().lower() for part in value.split(",") if part.strip()]
        unknown = sorted(set(requested) - set(known))
        if unknown:
            raise ValueError(
                f"unknown {what}(s): {', '.join(unknown)}; choose from {', '.join(known)}"
            )
        return tuple(name for name in known if name in requested)

    @staticmethod
    def fires(triggers: Sequence[str], *, gate: str, complete: bool) -> bool:
        """Whether a scan with this outcome is one the user asked to hear about."""
        return (
            (gate == "failed" and "failed" in triggers)
            or (not complete and "incomplete" in triggers)
            or (gate == "passed" and complete and "passed" in triggers)
        )

    def send(
        self,
        channels: Sequence[str],
        result: ScanResult,
        *,
        reason: str,
        exit_code: int,
        gate: str = "failed",
        test: bool = False,
    ) -> list[Delivery]:
        """Send to each channel, in parallel. Never raises: every failure is a `Delivery`."""
        summary = Summary.of(result, reason=reason, exit_code=exit_code, gate=gate, test=test)
        deadline = self._clock() + self._policy.deadline
        if not channels:
            return []
        with ThreadPoolExecutor(max_workers=len(channels), thread_name_prefix="notify") as pool:
            futures = [pool.submit(self._guarded, c, summary, deadline) for c in channels]
            return [future.result() for future in futures]

    def _guarded(self, channel: str, summary: Summary, deadline: float) -> Delivery:
        try:
            return self._send_one(channel, summary, deadline)
        except Exception as exc:  # a notifier must not take the scan down with it  # noqa: BLE001
            return Delivery(channel, False, type(exc).__name__)

    def _send_one(self, name: str, summary: Summary, deadline: float) -> Delivery:
        channel = self._channels.get(name)
        if channel is None:
            return Delivery(name, False, f"no notify channel named {name!r}")
        url = self._environ.get(channel.variable, "").strip()
        if not url:
            return Delivery(name, False, f"{channel.variable} is not set")
        if urllib.parse.urlsplit(url).scheme != "https":
            return Delivery(name, False, f"{channel.variable} must be an https URL")
        delivery = str(uuid.uuid4())
        occasion = Occasion(self._environ, delivery, int(self._clock()), int(self._clock() * 1000))
        try:
            message = channel.message(summary, occasion)
        except ChannelRefused as refused:
            return Delivery(name, False, str(refused), delivery=delivery)
        return self._deliver(name, url, message, delivery, deadline)

    def _deliver(
        self, name: str, url: str, message: Message, delivery: str, deadline: float
    ) -> Delivery:
        headers = {"Content-Type": "application/json", "User-Agent": HttpsTransport.USER_AGENT}
        headers.update(message.headers)
        error = ""
        for attempt in range(1, self._policy.attempts + 1):
            reply: Reply | None = None
            try:
                answer = self._transport(url, message.body, headers)
                reply = answer if isinstance(answer, Reply) else Reply(int(answer))
            except RetryPolicy.FAILURES as exc:
                error = f"{type(exc).__name__} delivering to {name}"
            except ValueError as exc:  # a malformed URL fails the same way every time
                return Delivery(
                    name, False, f"{type(exc).__name__} delivering to {name}", attempt, delivery
                )
            if reply is not None:
                if 200 <= reply.status < 300:
                    return Delivery(name, True, "", attempt, delivery)
                error = f"HTTP {reply.status} from {name}"
                if not RetryPolicy.retryable(reply.status):
                    return Delivery(name, False, error, attempt, delivery)
            wait = self._policy.wait(attempt, reply)
            last = attempt == self._policy.attempts
            if last or wait is None or self._clock() + wait > deadline:
                return Delivery(name, False, error, attempt, delivery)
            self._sleep(wait)
        return Delivery(name, False, error, self._policy.attempts, delivery)


__all__ = ["Delivery", "Notifier"]
