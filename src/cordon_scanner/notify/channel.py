"""The port a notification channel implements.

A channel turns a `Summary` into the body and headers its receiver expects. It does not post: the
`Notifier` does, through one transport with one retry policy, so every channel, a plugin's included,
gets HTTPS only, no redirects and the same limits. A channel is handed the `Summary` and never the
scan result, so it cannot send what a summary leaves out.

Channels register under the `cordon_scanner.notifiers` entry-point group, as detectors and
reporters do. A third party's channel loads only with plugins allowed (`allow_plugins`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.notify.summary import Summary


class ChannelRefused(Exception):
    """A channel will not build its message, and why: a missing secret, say. The reason is shown to
    the person running the scan, so it never contains a URL or a secret."""


@dataclass(frozen=True)
class Occasion:
    """What one delivery knows besides the summary."""

    environ: Mapping[str, str]
    """Where the channel reads its secrets. Its destination URL is read by the notifier."""
    delivery: str
    """The idempotency key, the same on every attempt."""
    now: int
    """Unix seconds, for a signature's timestamp."""
    sequence: int
    """Orders one source's events: milliseconds at send time."""


@dataclass(frozen=True)
class Message:
    """A channel's body, and the headers it adds to the notifier's own."""

    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


@runtime_checkable
class Channel(Protocol):
    """A place a notification can go."""

    id: str
    """The name on the command line: `--notify <id>`."""
    variable: str
    """The environment variable holding the destination URL."""

    def message(self, summary: Summary, occasion: Occasion) -> Message:
        """The body and headers for `summary`. Raises `ChannelRefused` to decline."""
        ...


__all__ = ["Channel", "ChannelRefused", "Message", "Occasion"]
