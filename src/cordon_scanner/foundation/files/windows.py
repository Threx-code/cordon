"""The whole of a file too large to read at once, read a window at a time.

Every rule reads the first `max_file_bytes` of a file. What lies past that was read by nine rules
(a sweep of the capability detector's), from a copy of the whole file held in memory, and only up to
`max_stream_bytes` -- so a payload past the first ten megabytes was invisible to every secret,
obfuscation, exfiltration and dropper rule, and past sixty-four to all of them. Padding a bundle
is cheap: an inert token placed after twelve megabytes of filler was found by nothing (review 98).

Here the rest of the file is cut into windows of at most `max_file_bytes`, each overlapping the one
before by `OVERLAP` and starting on a line where it can, and every detector that judges text
(`engine.window_pass.WINDOW_DETECTORS`) reads each window as it would a small file. Findings are moved to their place
in the whole file and repeats from the overlaps dropped. A file on disk is read from disk, window
by window, so memory holds one window rather than the file; an archive member is already in memory
as the archive's bytes.

```
  bytes  0 ............ max_file_bytes ......................................... size
         [ every rule: the prefix ]
                           [ window 1 ]
                                   [ window 2 ]          each <= max_file_bytes, overlapping
                                            [ window 3 ] by OVERLAP, on a line boundary
  read up to max_stream_bytes; 0 turns the windows off
```

Detectors that judge a file as a whole -- its format, its structure, its manifest -- do not read
windows: a window of a lockfile is not a lockfile.
"""

from __future__ import annotations

import contextlib
import os
import stat as stat_module
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

OVERLAP = 64 * 1024
"""How far each window reaches back into the one before: a construct that straddles a cut -- a
command and the prompt it carries, a key split across two lines -- is whole in one of them."""


class WindowSourceChanged(Exception):
    """The file was replaced or changed between being read and being read again."""


class WindowSource:
    """Somewhere the whole of an oversized file can be read from, a range at a time."""

    size: int

    @contextlib.contextmanager
    def reader(self) -> Iterator[Callable[[int, int], bytes]]:
        raise NotImplementedError


@dataclass(frozen=True)
class BytesWindows(WindowSource):
    """A file already held in memory: an archive member."""

    data: bytes

    @property
    def size(self) -> int:  # type: ignore[override]
        return len(self.data)

    @contextlib.contextmanager
    def reader(self) -> Iterator[Callable[[int, int], bytes]]:
        yield lambda offset, length: self.data[offset : offset + length]


@dataclass(frozen=True)
class DiskWindows(WindowSource):
    """A file on disk, opened again the way `FileContent.load` opened it, and refused if it is
    no longer the file that was read: a symlink now, or another inode, size or mtime."""

    path: str
    identity: tuple[int, int, int, int]
    """(st_dev, st_ino, st_size, st_mtime_ns) when it was first read."""

    @property
    def size(self) -> int:  # type: ignore[override]
        return self.identity[2]

    @staticmethod
    def identity_of(stat: os.stat_result) -> tuple[int, int, int, int]:
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    @contextlib.contextmanager
    def reader(self) -> Iterator[Callable[[int, int], bytes]]:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise WindowSourceChanged(str(exc)) from exc
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            stat = os.fstat(handle.fileno())
            if not stat_module.S_ISREG(stat.st_mode) or self.identity_of(stat) != self.identity:
                raise WindowSourceChanged("the file changed after it was first read")

            def read(offset: int, length: int) -> bytes:
                handle.seek(offset)
                return handle.read(length)

            yield read


class SeekableReader:
    """A read-only, seekable file over a `WindowSource` reader, for a library that seeks rather
    than streams -- `zipfile` reads a zip's index from the end, then each member from its offset.
    Each read is a range from the source; the file is never held in memory. Only the methods such a
    library uses are provided (`seek`, `tell`, `read`, `seekable`)."""

    def __init__(self, read: Callable[[int, int], bytes], size: int) -> None:
        self._read = read
        self._size = size
        self._pos = 0

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR:
            self._pos += offset
        elif whence == os.SEEK_END:
            self._pos = self._size + offset
        else:  # pragma: no cover - the stdlib never passes another whence
            raise ValueError(f"invalid whence: {whence}")
        return self._pos

    def read(self, size: int | None = -1) -> bytes:
        length = self._size - self._pos if size is None or size < 0 else size
        data = self._read(self._pos, length)
        self._pos += len(data)
        return data


@dataclass(frozen=True)
class Window:
    begin: int
    """Byte offset of the window in the whole file."""
    lines_before: int
    """Newlines in the whole file before `begin`: add to a window's line to place it."""
    data: bytes


class Windows:
    @staticmethod
    def iterate(
        source: WindowSource, prefix: bytes, *, size: int, overlap: int, limit: int
    ) -> Iterator[Window]:
        """The windows covering `source` past `prefix` (its first bytes, already examined), up to
        `limit` bytes of the file. Each starts on a line inside its overlap where it can and ends
        on one where it can; a single line longer than a window is cut where it has to be, and the
        overlap keeps what spans the cut whole in the next."""
        end_limit = min(source.size, limit)
        start = len(prefix)
        if start >= end_limit or size <= 0:
            return
        with source.reader() as read:
            known_at, known_lines = 0, 0
            reference = prefix
            while start < end_limit:
                begin = max(0, start - overlap)
                head = read(begin, start - begin)
                newline = head.find(b"\n")
                if newline != -1:
                    begin += newline + 1
                stop = min(end_limit, start + size)
                data = read(begin, stop - begin)
                if not data:
                    return
                if stop < end_limit:
                    cut = data.rfind(b"\n")
                    if cut + 1 > start - begin:
                        data = data[: cut + 1]
                        stop = begin + cut + 1
                # Newlines before `begin`, counted from the last place they were known.
                lines = known_lines + reference[: begin - known_at].count(b"\n")
                yield Window(begin=begin, lines_before=lines, data=data)
                known_at, known_lines, reference = begin, lines, data
                start = begin + len(data)
