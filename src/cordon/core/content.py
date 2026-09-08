"""Lazy file content.

Every detector that looks at a file looks at it through this class, and it exists
for two reasons.

**Performance.** The naive shape reads and decodes each file once per detector,
which on a large repository is most of the runtime. ``FileContent`` reads once,
memoises the derived forms, and is shared across all detectors examining that
file. Latency is a security property here: a commit-time guard that costs
noticeably more than a second gets bypassed, and a bypassed guard protects
nothing.

**Safety.** It is also the choke point where a hostile file meets the scanner, so
the limits live here rather than in each caller. Decoding is deferred until a
detector actually needs text, because the large majority of files match nothing
and decoding them is pure waste -- and because decoding attacker-controlled bytes
is a step worth taking only when something has already indicated it is worth it.
"""

from __future__ import annotations

import hashlib
import mmap
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.limits import DEFAULT_LIMITS, Limits

if TYPE_CHECKING:
    from collections.abc import Sequence

BINARY_SNIFF_BYTES = 8192
"""How much of a file to inspect when deciding whether it is binary.

A NUL byte in the first 8 KiB is the same heuristic grep uses for its -I flag. It
is not perfect, and it does not need to be: the cost of a false "binary" is one
unscanned file that is reported as skipped, and the cost of a false "text" is a
handful of meaningless matches. Both are visible; neither is silent.
"""


class SkipReason:
    """Why a file was not fully scanned.

    Every value here becomes an OPERATIONAL finding. A file that is silently
    skipped is indistinguishable from a file that was scanned and found clean,
    and a scanner whose coverage quietly shrinks is the most dangerous failure
    mode available to one.
    """

    TOO_LARGE = "too_large"
    BINARY = "binary"
    UNREADABLE = "unreadable"
    DECODE_FAILED = "decode_failed"
    SYMLINK = "symlink"
    NOT_REGULAR = "not_regular"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class Skipped:
    """A file that was not scanned, and the reason."""

    path: str
    reason: str
    detail: str = ""


@dataclass
class FileContent:
    """One file's bytes and everything derived from them.

    Not frozen, because the memoised properties are computed on demand. It is
    still treated as immutable by every consumer: nothing mutates ``raw``.

    Construct via :meth:`load`, which applies the limits. Constructing directly
    bypasses them.
    """

    path: str
    """Repository-relative, forward-slashed. What appears in a finding."""

    raw: bytes
    size: int
    limits: Limits = field(default=DEFAULT_LIMITS, repr=False)
    truncated: bool = False
    """True when only a prefix of the file was read. Detectors that need whole-
    file reasoning (entropy over the file, longest-line) must check this rather
    than silently computing over a fragment."""

    # -- Construction ----------------------------------------------------

    @classmethod
    def load(
        cls,
        real_path: Path,
        rel_path: str,
        limits: Limits = DEFAULT_LIMITS,
    ) -> FileContent | Skipped:
        """Read a file, applying limits.

        Returns :class:`Skipped` rather than raising, because one unreadable
        file must never abort a scan of ten thousand. The caller turns the
        Skipped into an OPERATIONAL finding.
        """
        try:
            stat = real_path.lstat()
        except OSError as exc:
            return Skipped(rel_path, SkipReason.UNREADABLE, str(exc))

        # Symlinks are inventoried but never followed. Following one is how a
        # scanner is made to read a private key outside the scan root and then
        # print it as evidence.
        import stat as stat_module

        if stat_module.S_ISLNK(stat.st_mode):
            return Skipped(rel_path, SkipReason.SYMLINK, "symlinks are not followed")
        if not stat_module.S_ISREG(stat.st_mode):
            return Skipped(rel_path, SkipReason.NOT_REGULAR, "not a regular file")

        size = stat.st_size

        try:
            if size > limits.max_file_bytes:
                # Read a bounded prefix rather than nothing. A payload appended
                # to a large generated file is still worth finding, and the
                # truncation is recorded so nothing claims full coverage.
                with real_path.open("rb") as handle:
                    raw = handle.read(limits.max_file_bytes)
                return cls(path=rel_path, raw=raw, size=size, limits=limits, truncated=True)

            if size >= limits.mmap_threshold:
                with (
                    real_path.open("rb") as handle,
                    mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
                ):
                    raw = bytes(mapped)
            else:
                raw = real_path.read_bytes()
        except (OSError, ValueError) as exc:
            return Skipped(rel_path, SkipReason.UNREADABLE, str(exc))

        return cls(path=rel_path, raw=raw, size=size, limits=limits)

    @classmethod
    def from_bytes(cls, path: str, raw: bytes, limits: Limits = DEFAULT_LIMITS) -> FileContent:
        """Build from bytes already in memory.

        Used for archive members, staged git blobs and tests, all of which have
        content but no readable path on disk.
        """
        return cls(path=path, raw=raw, size=len(raw), limits=limits)

    # -- Derived forms ---------------------------------------------------

    @cached_property
    def is_binary(self) -> bool:
        return b"\x00" in self.raw[:BINARY_SNIFF_BYTES]

    @cached_property
    def sha256(self) -> str:
        """Content hash. The incremental cache key and the artefact identity."""
        return hashlib.sha256(self.raw).hexdigest()

    @cached_property
    def text(self) -> str:
        """Decoded content.

        Decoded permissively with ``errors="replace"``. A file that is 99 percent
        valid UTF-8 with a few stray bytes is common in real repositories, and it
        is also exactly what a payload hiding behind an encoding trick looks
        like. Refusing to decode would skip both; replacing the bad bytes scans
        both.

        Byte offsets from a byte-level match do not index into this string. That
        is why :class:`Location` carries both, and why evidence extraction works
        from ``raw``.
        """
        encoding = "utf-8"
        if self.raw.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
        elif self.raw.startswith((b"\xff\xfe", b"\xfe\xff")) and self._looks_utf16():
            encoding = "utf-16"
        try:
            return self.raw.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            return self.raw.decode("latin-1", errors="replace")

    def _looks_utf16(self) -> bool:
        """Corroborate a UTF-16 byte-order mark before trusting it.

        Those two bytes are not rare, and any file whose content happens to
        begin with them was previously decoded as UTF-16 and turned into noise.
        Real UTF-16 text over a mostly-ASCII alphabet is half NUL bytes, so
        their absence is decisive.
        """
        window = self.raw[2:66]
        return b"\x00" in window

    @cached_property
    def line_starts(self) -> tuple[int, ...]:
        """Byte offset of the start of each line.

        Computed once and binary-searched, so translating a byte offset into a
        line number is logarithmic rather than a scan of the file. With thousands
        of matches across thousands of files, the naive version is measurable.
        """
        starts = [0]
        start = 0
        while True:
            found = self.raw.find(b"\n", start)
            if found == -1:
                break
            starts.append(found + 1)
            start = found + 1
        return tuple(starts)

    @cached_property
    def line_count(self) -> int:
        return len(self.line_starts)

    @cached_property
    def longest_line(self) -> int:
        """Length in bytes of the longest line.

        A payload appended to a source file is frequently one very long line,
        because that is what keeps it off-screen in a diff view and out of the
        reviewer's eye. The measurement is cheap and the signal is real, though
        it needs calibrating against minified files, which are legitimately made
        of very long lines. That calibration is the detector's job, not this
        class's.
        """
        longest = 0
        previous = 0
        for start in self.line_starts[1:]:
            # `- 1` drops the newline; the extra `- 1` drops a carriage return
            # when the file uses CRLF. Counting it would make the same content
            # measure differently depending on how it was checked out.
            end = start - 1
            if end > previous and self.raw[end - 1 : end] == b"\r":
                end -= 1
            longest = max(longest, end - previous)
            previous = start

        tail = len(self.raw)
        if tail > previous and self.raw[tail - 1 : tail] == b"\r":
            tail -= 1
        return max(longest, tail - previous)

    # -- Position translation --------------------------------------------

    def line_of(self, byte_offset: int) -> int:
        """1-indexed line number containing a byte offset."""
        from bisect import bisect_right

        return bisect_right(self.line_starts, byte_offset)

    def column_of(self, byte_offset: int) -> int:
        """1-indexed column, in bytes, of an offset within its line."""
        line = self.line_of(byte_offset)
        return byte_offset - self.line_starts[line - 1] + 1

    def line_text(self, line_number: int) -> str:
        """One line's text, bounded by ``max_line_bytes``.

        The bound matters: a one-gigabyte single line is either minified output
        or an attack on the line-slicing code, and neither should be
        materialised in full to print an error message about it.
        """
        if line_number < 1 or line_number > len(self.line_starts):
            return ""
        start = self.line_starts[line_number - 1]
        end = (
            self.line_starts[line_number] if line_number < len(self.line_starts) else len(self.raw)
        )
        end = min(end, start + self.limits.max_line_bytes)
        # Both terminators are stripped. A CRLF checkout would otherwise carry a
        # trailing carriage return into every evidence snippet, and the same
        # repository checked out with different line endings would produce
        # different output -- which breaks the determinism guarantee across
        # platforms rather than merely looking untidy.
        return self.raw[start:end].decode("utf-8", errors="replace").rstrip("\r\n")

    def slice(self, start: int, end: int) -> bytes:
        """Bounded byte slice, for evidence extraction."""
        start = max(0, start)
        end = min(len(self.raw), max(start, end))
        return self.raw[start:end]

    # -- Convenience -----------------------------------------------------

    @property
    def extension(self) -> str:
        _, _, ext = self.path.rpartition(".")
        return f".{ext.lower()}" if ext and "/" not in ext else ""

    @property
    def basename(self) -> str:
        return self.path.rpartition("/")[2]

    @cached_property
    def shebang(self) -> str | None:
        """The interpreter named on the first line, if any.

        Needed because extension alone misidentifies files, and a scanner that
        misidentifies a language applies the wrong rules to it. Executable
        scripts with no extension are common and are exactly the kind of file
        worth reading carefully.
        """
        if not self.raw.startswith(b"#!"):
            return None
        end = self.raw.find(b"\n", 0, 256)
        line = self.raw[2 : end if end != -1 else 256]
        return line.decode("utf-8", errors="replace").strip() or None

    def __len__(self) -> int:
        return len(self.raw)

    def __repr__(self) -> str:
        return f"FileContent({self.path!r}, {self.size} bytes)"


def sniff_language(content: FileContent, extension_map: Sequence[tuple[str, str]]) -> str | None:
    """Identify a file's language from extension, then shebang.

    Extension first because it is right the overwhelming majority of the time and
    costs nothing. Shebang second because it is authoritative when present: a
    file declaring an interpreter is telling you what will execute it, which
    beats any inference from its name.
    """
    ext = content.extension
    if ext:
        for suffix, language in extension_map:
            if suffix == ext:
                return language

    shebang = content.shebang
    if shebang:
        interpreter = shebang.split("/")[-1].split()[0] if "/" in shebang else shebang.split()[0]
        # `#!/usr/bin/env python3` names env, not the interpreter. The real one
        # is the argument, and this form is more common than the direct path.
        if interpreter == "env" and " " in shebang:
            interpreter = shebang.split()[-1]
        for suffix, language in extension_map:
            if suffix.lstrip(".") == interpreter:
                return language
        return interpreter or None

    return None


__all__ = [
    "BINARY_SNIFF_BYTES",
    "FileContent",
    "SkipReason",
    "Skipped",
    "sniff_language",
]
