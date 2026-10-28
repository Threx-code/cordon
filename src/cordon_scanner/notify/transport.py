"""Posting a message: HTTPS only, no redirects, a timeout, and when to try again.

A redirect is never followed: it could turn an https destination into an http one. A delivery is
tried again only when trying again can help -- the connection failed, or the receiver said it was
busy or broken (408, 429, 5xx) -- and never on any other 4xx, where a wrong URL or a revoked hook
stays wrong however often it is posted to.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from cordon_scanner.version import __version__


@dataclass(frozen=True)
class Reply:
    """What the receiver answered: its status, and how long it asked us to wait, if it did."""

    status: int
    retry_after: float | None = None


Transport = Callable[[str, bytes, Mapping[str, str]], "Reply | int"]
"""Posts a body and returns the receiver's `Reply` (or just its status). Replaced in tests."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpsTransport:
    """POST over HTTPS without following redirects."""

    TIMEOUT_SECONDS: Final = 5.0
    USER_AGENT: Final = f"cordon-scanner/{__version__} (+https://github.com/Threx-code/cordon)"

    @staticmethod
    def post(url: str, body: bytes, headers: Mapping[str, str]) -> Reply:
        request = urllib.request.Request(  # noqa: S310  (scheme checked by the caller)
            url, data=body, headers=dict(headers), method="POST"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=HttpsTransport.TIMEOUT_SECONDS) as response:
                return Reply(int(response.status))
        except urllib.error.HTTPError as exc:
            return Reply(int(exc.code), RetryPolicy.seconds(exc.headers.get("Retry-After")))


@dataclass(frozen=True)
class RetryPolicy:
    """How many times, how long between, and how long in all."""

    attempts: int = 3
    backoff: tuple[float, ...] = (1.0, 2.0)
    """The wait before the second attempt, the third, and so on (the last repeats)."""
    longest_wait: float = 10.0
    """A receiver's `Retry-After` is honoured up to this; a longer one is not waited for."""
    deadline: float = 20.0
    """Seconds for every channel's every attempt, from the first: a scan never waits longer."""

    FAILURES: ClassVar[tuple[type[BaseException], ...]] = (
        urllib.error.URLError,
        http.client.HTTPException,
        OSError,
    )
    """What a failed attempt raises. A `ValueError` (a malformed URL) is not among them: it would
    fail the same way every time."""

    @staticmethod
    def retryable(status: int) -> bool:
        return status in (408, 429) or 500 <= status < 600

    def wait(self, attempt: int, reply: Reply | None) -> float | None:
        """Seconds to wait before attempt `attempt + 1`, or None when the receiver asked for longer
        than `longest_wait`."""
        planned = self.backoff[min(attempt - 1, len(self.backoff) - 1)] if self.backoff else 0.0
        asked = reply.retry_after if reply is not None else None
        if asked is None:
            return planned
        if asked > self.longest_wait:
            return None
        return max(planned, asked)

    @staticmethod
    def seconds(value: str | None) -> float | None:
        """A `Retry-After` given in seconds. The HTTP-date form is not honoured: it would have the
        scan trust the receiver's clock."""
        if not value:
            return None
        try:
            seconds = float(value.strip())
        except ValueError:
            return None
        return seconds if seconds >= 0 else None


__all__ = ["HttpsTransport", "Reply", "RetryPolicy", "Transport"]
