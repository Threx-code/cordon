"""Reading a network response's body within a time budget for the whole body.

A socket timeout bounds one read. It does not bound a download: a server, a proxy or a broken path
that sends a byte now and then never lets one read wait long, and `response.read(n)` waits until
`n` bytes have come. Measured: a body of 200 bytes sent one byte every 0.1 s took 20.3 s to read
under a 3 s timeout; the feed's 1 MB metadata limit at a byte every 2.9 s would take 35 days, and
every scan with the feed enabled reads it before it starts.

So every body is read through here: `read1` returns whatever has arrived, at most one socket wait,
and the budget is checked between reads. Past it, `TimeoutError` -- an `OSError`, so every caller's
handling of an unreachable server applies unchanged.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

CHUNK = 64 * 1024
"""The most one read asks for."""

BUDGET_SECONDS = 120.0
"""A body's budget when its caller names none: generous for any size this package downloads at a
working connection's speed, and an end to a connection that is not working."""


class Download:
    """A network response's body, read within a budget for the whole of it."""

    @staticmethod
    def read(response: Any, limit: int, *, budget: float = BUDGET_SECONDS) -> bytes:
        """Up to `limit` bytes of `response`'s body: all of it when it is shorter, the first `limit`
        when it is longer, so a caller asking for `limit + 1` can tell a body over its cap.

        Raises `TimeoutError` when the body has not arrived within `budget` seconds.

        An object without `read1` is read once, as before: every response urllib returns has it
        (an `HTTPError` through the response it wraps), so only a stand-in does not, and a stand-in
        that ignores the size it is asked for would otherwise be read again forever."""
        if not hasattr(response, "read1"):
            return bytes(response.read(limit))[:limit]
        parts: list[bytes] = []
        received = 0
        for chunk in Download.chunks(response, budget=budget, size=min(CHUNK, max(1, limit))):
            parts.append(chunk)
            received += len(chunk)
            if received >= limit:
                break
        return b"".join(parts)[:limit]

    @staticmethod
    def chunks(
        response: Any, *, budget: float = BUDGET_SECONDS, size: int = CHUNK
    ) -> Iterator[bytes]:
        """`response`'s body as it arrives, each chunk at most `size` bytes, the whole within
        `budget` seconds. For a body the caller streams to disk or into a decompressor."""
        deadline = time.monotonic() + budget
        read = getattr(response, "read1", None) or response.read
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f"the response did not arrive within {budget:.0f}s")
            chunk = read(size)
            if not chunk:
                return
            yield chunk


__all__ = ["BUDGET_SECONDS", "CHUNK", "Download"]
