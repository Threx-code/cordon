"""Reporting what a scan is doing while it does it.

A scan of a large repository takes long enough that silence is indistinguishable
from a hang, and the reasonable response to a tool that appears hung is to kill
it. A scanner people interrupt is a scanner that reports nothing, which is the
same outcome as a scanner that finds nothing -- the failure this whole project
is organised around.

Three properties make this safe to add to a security tool rather than merely
nice:

**It cannot change the result.** The engine calls into a `Progress`, and the
protocol returns nothing. There is no path by which a display decision reaches a
finding, and a test asserts that a scan with progress and a scan without produce
identical findings.

**It cannot reach standard output.** A report is written to stdout when no
`--output` is given, so anything else printed there corrupts the JSON or SARIF a
pipeline is parsing. Progress belongs on stderr, and the renderer is the only
thing that decides where its bytes go.

**It never renders scanned text.** The only scanned value it shows is a path,
and a path is attacker-chosen. It goes through `Escape.terminal` first, because
a filename may legally contain an ANSI escape or a bidirectional override and
writing one straight to a terminal lets the scanned repository rewrite the
scanner's own output.

The default is `NullProgress`, so nothing outside the CLI has to know this
exists.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Progress(Protocol):
    """Somewhere to report what a scan is currently doing.

    Every method returns `None` and no method may raise: a renderer that fails
    must not be able to fail the scan it is describing. Implementations are
    called from the process that owns the scan, never from a worker.
    """

    def phase(self, name: str, total: int | None = None) -> None:
        """Begin a named stage, optionally of a known size."""

    def advance(self, path: str = "") -> None:
        """One unit of the current phase is done, optionally naming it."""

    def note(self, message: str) -> None:
        """State something the reader should see even when phases are quiet."""

    def finish(self) -> None:
        """Release the display. Called once, including when a scan fails."""


class NullProgress:
    """The default: reports nothing, costs nothing.

    A class rather than `None` checks scattered through the engine. The engine
    calls the same four methods whatever is configured, so there is no branch
    that can be wrong in only one of the two modes -- which is how a display
    feature ends up changing behaviour.
    """

    __slots__ = ()

    def phase(self, name: str, total: int | None = None) -> None:
        return None

    def advance(self, path: str = "") -> None:
        return None

    def note(self, message: str) -> None:
        return None

    def finish(self) -> None:
        return None


__all__ = ["NullProgress", "Progress"]
