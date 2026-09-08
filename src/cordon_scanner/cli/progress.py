"""A live progress line for an interactive terminal.

What it looks like, on one line that rewrites itself:

    scanning  [############--------]  312/521  38%  src/app/handlers.py

Everything about it is arranged so that it can be wrong without the scan being
wrong.

**Standard error, always.** A report goes to stdout when `--output` is not
given, so a byte of progress there corrupts the JSON or SARIF a pipeline is
parsing. Nothing in this file writes to stdout.

**Off unless a human is watching.** Enabled only when stderr is a terminal.
Carriage-return redrawing in a CI log produces one enormous line of interleaved
frames, so the default has to be decided by what stderr is attached to rather
than by a flag people would have to remember in every workflow.

**Throttled.** A repository with fifty thousand small files would otherwise
spend more time drawing than scanning. Frames are rate-limited and the terminal
is written to at most every `MIN_REDRAW`; the counter still counts every file.

**It never trusts a path.** Paths come from the scanned repository and go
through `Escape.terminal` before they reach the terminal.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from typing import Any, TextIO

from cordon_scanner.report.base import Escape

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"

MIN_REDRAW = 0.05
"""Seconds between terminal writes.

Twenty frames a second reads as continuous to a person and costs nothing next to
the work between frames. Without a floor, a tree of many small files spends a
measurable share of the scan formatting lines nobody sees."""

MAX_PATH = 48
"""Characters of path to show, from the right.

The tail identifies a file; the head is the part every path in the repository
has in common. Truncation keeps the line inside a narrow terminal without
wrapping, and a wrapped progress line leaves debris on the screen because the
carriage return only returns to the start of the last row."""


class _Discard:
    """Stands in for a stream that has gone away."""

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None


class TerminalProgress:
    """Draws the current phase and file onto one rewritten line."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        color: bool = True,
        min_redraw: float = MIN_REDRAW,
    ) -> None:
        self.stream: Any = stream if stream is not None else sys.stderr
        self.color = color
        # Injectable so a test can assert what a frame contains without racing
        # the throttle. Left at the default everywhere else.
        self.min_redraw = min_redraw
        self._phase = ""
        self._total: int | None = None
        self._done = 0
        self._last_draw = 0.0
        self._dirty = False

    # -- Protocol --------------------------------------------------------

    def phase(self, name: str, total: int | None = None) -> None:
        self._phase = name
        self._total = total
        self._done = 0
        self._draw(force=True)

    def advance(self, path: str = "") -> None:
        self._done += 1
        self._draw(path=path)

    def note(self, message: str) -> None:
        """Print a standalone line above the progress line.

        The progress line is cleared first and redrawn after, so a note never
        lands halfway through a frame and leave half of it on screen."""
        self._clear()
        self._write(f"{self._tint(DIM)}{Escape.terminal(message)}{self._tint(RESET)}\n")
        self._draw(force=True)

    def finish(self) -> None:
        self._clear()

    # -- Rendering -------------------------------------------------------

    def _tint(self, code: str) -> str:
        return code if self.color else ""

    def _write(self, text: str) -> None:
        """Write, and give up permanently if the stream has gone.

        `cordon-scanner scan . | head` closes the pipe, and a progress line that
        raises there would turn a display detail into a failed scan. The scan is
        the product; this is commentary on it."""
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            # ValueError is what a closed file object raises. Both mean there is
            # nowhere left to draw, so stop trying rather than raising per file.
            self.stream = _Discard()

    def _draw(self, path: str = "", *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_draw < self.min_redraw:
            self._dirty = True
            return
        self._last_draw = now
        self._dirty = False

        width = self._width()
        line = self._compose(path, width)
        # Cleared to the end of the line rather than padded with spaces: a
        # shorter frame following a longer one would otherwise leave the tail of
        # the previous path on screen, which reads as the scanner being stuck on
        # a file it finished with.
        self._write(f"\r{line}\033[K" if self.color else f"\r{line:<{width - 1}}")

    def _compose(self, path: str, width: int) -> str:
        parts = [f"{self._tint(BOLD)}{self._phase:<10}{self._tint(RESET)}"]
        # Tracked alongside the coloured parts because colour codes occupy no
        # columns, so `len` of the assembled string is not its width.
        columns = 10

        if self._total:
            share = min(self._done / self._total, 1.0)
            filled = int(share * 20)
            bar = "#" * filled + "-" * (20 - filled)
            counter = f"{self._done}/{self._total}"
            parts.append(f"{self._tint(CYAN)}[{bar}]{self._tint(RESET)}")
            parts.append(counter)
            parts.append(f"{share:>4.0%}")
            columns += 2 + 22 + 2 + len(counter) + 2 + 4
        elif self._done:
            counter = str(self._done)
            parts.append(counter)
            columns += 2 + len(counter)

        if path:
            # Sized to what is actually left rather than to a fixed budget, and
            # trimmed from the left. Trimming the whole line from the right
            # instead cut the filename off the end -- the one part of a path
            # that identifies anything, leaving `.../nested/nested/nested`.
            room = min(MAX_PATH, width - columns - 4)
            shortened = self._shorten(path, room)
            if shortened:
                parts.append(f"{self._tint(DIM)}{shortened}{self._tint(RESET)}")

        return self._fit("  ".join(parts), width)

    @staticmethod
    def _shorten(path: str, room: int) -> str:
        """The tail of a path, which is the part that names the file.

        Escaped first: a path that expands under escaping must not be measured
        by its raw length, or the escaped form overflows the width computed for
        it."""
        if room < 8:
            return ""
        safe = Escape.terminal(path)
        if len(safe) <= room:
            return safe
        return "..." + safe[-(room - 3) :]

    def _fit(self, line: str, width: int) -> str:
        """Trim to the terminal width, counting printed characters only.

        Colour codes occupy no columns, so measuring the raw string would trim a
        line that fits and wrap one that does not."""
        if not self.color:
            return line[: width - 1]
        visible = 0
        out: list[str] = []
        index = 0
        while index < len(line):
            if line[index] == "\033":
                end = line.find("m", index)
                if end == -1:
                    break
                out.append(line[index : end + 1])
                index = end + 1
                continue
            if visible >= width - 1:
                break
            out.append(line[index])
            visible += 1
            index += 1
        rendered = "".join(out)
        # Only if the trim actually cut through a coloured span. Appending
        # unconditionally left `\033[0m\033[0m` on every frame.
        return rendered if rendered.endswith(RESET) else rendered + RESET

    def _clear(self) -> None:
        self._write("\r\033[K" if self.color else "\r" + " " * (self._width() - 1) + "\r")

    def _width(self) -> int:
        try:
            return max(shutil.get_terminal_size().columns, 40)
        except OSError:  # pragma: no cover - no controlling terminal
            return 80


def should_show(stream: TextIO, mode: str, *, quiet: bool) -> bool:
    """Whether to draw progress at all.

    `auto` is the default and asks what stderr is attached to. A terminal means
    somebody is waiting; a pipe or a file means a log, where a rewritten line
    becomes one unreadable row. `always` is for a terminal Python cannot detect,
    `never` for a terminal where it is unwanted.

    `--quiet` wins over all three: it asks for findings only, and a progress
    line is not a finding.
    """
    if quiet or mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("CI"):
        # Many CI runners allocate a pseudo-terminal, which makes `isatty` true
        # in a place where the output is only ever read as a log file.
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


__all__ = ["TerminalProgress", "should_show"]
