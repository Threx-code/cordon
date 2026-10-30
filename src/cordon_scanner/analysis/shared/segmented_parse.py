"""A large JavaScript or TypeScript file parsed whole, a segment at a time, in bounded memory.

The capability detector's `kind: ast` tier parsed each piece of a large file it was given: the
prefix every rule reads and each window past it. A piece of a one-line 24 MB bundle starts and
ends inside a string, and the parser then in use (tree-sitter) took 32 seconds recovering on 10 MB
where the whole file parses in half a second (review 98: 189 of a 337-second scan). What it
recovered from was a string read as code: the calls it reported there were not calls.

So a file past `max_file_bytes` is parsed once, whole, in segments cut where a statement ends --
after a `;` or `}` at the shallowest depth near the segment's end, found by the scanner's own
tokenizer -- so each segment is code a parser reads as code, cheaply. A segment's tree is released
before the next is parsed: 25 MB of dense code is a 1.3 GB tree whole, a few hundred MB a segment.
A literal or comment too long for a segment is given to the parser as filler of its own length, so
every byte offset stays the file's own and neither the literal nor its parse is held.

Every call is placed by its byte offset in the file, and each piece the detector is given -- the
prefix, a window -- takes the calls that start inside it, at its own line and column.
"""

from __future__ import annotations

import bisect
import re
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.files.windows import WindowSourceChanged

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from cordon_scanner.analysis.python.pyfacts import AstCall
    from cordon_scanner.foundation.files.windows import WindowSource

    Read = Callable[[int, int], bytes]


@dataclass(frozen=True)
class Segment:
    """Bytes `start` to `end` of the file; `line` newlines and `column` bytes precede `start` on
    its line; `masks` are ranges read as filler."""

    start: int
    end: int
    line: int
    column: int
    masks: tuple[tuple[int, int], ...] = ()


class SegmentView:
    """One segment as the parser and the node readers see it: read by range from the file, the
    masked ranges as filler. Offsets are the segment's own, as the parser's are."""

    CHUNK: ClassVar[int] = 1 << 16
    #: The most of one node's text read: a literal argument megabytes long folds to its first
    #: megabyte, as no pattern an `ast` rule names is longer.
    NODE_TEXT: ClassVar[int] = 1 << 20

    def __init__(self, read: Read, segment: Segment) -> None:
        self._read, self._segment = read, segment

    def read(self, offset: int, _point: Any = None) -> bytes:
        """The parser's callback: the bytes from `offset` on."""
        length = self._segment.end - self._segment.start
        if offset >= length:
            return b""
        return self._range(self._segment.start + offset, min(SegmentView.CHUNK, length - offset))

    def __getitem__(self, key: slice) -> bytes:
        start = self._segment.start + (key.start or 0)
        stop = self._segment.start + (key.stop if key.stop is not None else 0)
        return self._range(start, min(max(stop - start, 0), SegmentView.NODE_TEXT))

    def _range(self, start: int, length: int) -> bytes:
        data = bytearray(self._read(start, length))
        for begin, end in self._segment.masks:
            lo, hi = max(begin, start), min(end, start + len(data))
            if lo < hi:
                data[lo - start : hi - start] = b"x" * (hi - lo)
        return bytes(data)


class Segments:
    """Where a large file is cut for parsing."""

    SIZE: ClassVar[int] = 4 << 20
    #: A cut is looked for in this last part of a segment.
    TAIL: ClassVar[int] = 1 << 20
    #: The most a segment grows to find a statement's end before it is cut where it stands.
    GROWN: ClassVar[int] = 64 << 20
    _OPEN: ClassVar[tuple[tuple[str, str], ...]] = (
        ("/*", "*/"),
        ("//", "\n"),
        ("`", "`"),
        ('"', '"'),
        ("'", "'"),
    )

    @staticmethod
    def of(read: Read, size: int) -> Iterator[Segment]:
        start = line = column = 0
        while start < size:
            end, masks = Segments._next_cut(read, start, size)
            if end <= start:
                return
            yield Segment(start, end, line, column, masks)
            line, column = Segments._advance(read, start, end, line, column)
            start = end

    @staticmethod
    def _next_cut(read: Read, start: int, size: int) -> tuple[int, tuple[tuple[int, int], ...]]:
        """Where the segment from `start` ends. Grown, up to `GROWN`, rather than cut anywhere
        but between statements: a cut inside an expression -- in an array of objects, a call's
        arguments -- costs the parser what a cut inside a string does."""
        length = Segments.SIZE
        while True:
            text = read(start, length).decode("latin-1")
            if start + len(text) >= size or not text:
                return size, ()
            cut = Segments._cut(read, start, text, size)
            if cut is not None or length >= Segments.GROWN:
                return cut if cut is not None else (start + len(text), ())
            length *= 2

    @staticmethod
    def _cut(
        read: Read, start: int, text: str, size: int
    ) -> tuple[int, tuple[tuple[int, int], ...]] | None:
        """The end of the last statement at the shallowest depth in the text's tail -- a `;`, or
        failing one a line break -- or, when a literal or comment runs past the text, its end,
        with its inside masked. None when the tail holds neither."""
        best, opened, opener = Segments._statement_ends(text, len(text) - Segments.TAIL)
        if best is not None:
            return start + best, ()
        pair = next((p for p in Segments._OPEN if p[0] == opener), None)
        if opened < 0 or pair is None:
            return None
        body = start + opened + len(pair[0])
        close = Segments._closing(read, body, size, pair[1])
        return min(close + len(pair[1]), size), ((body, close),)

    #: What changes the scanner's state: an escape, a quote, a template interpolation, a comment
    #: or regular expression delimiter, a bracket, a statement end, a line break.
    _SPECIAL: ClassVar[re.Pattern[str]] = re.compile(
        r"\\.|[\"'`]|\$\{|/\*|\*/|//|/|[;{}()\[\]\n]", re.S
    )
    #: What a `/` follows when it opens a regular expression rather than divides.
    _REGEX_AFTER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|[(,=:\[!&|?{};+\-*%<>~^]|\b(?:return|typeof|case|in|of|delete|void|throw|new|else|do|"
        r"yield|await|instanceof))\s*$"
    )

    @staticmethod
    def _statement_ends(text: str, tail: int) -> tuple[int | None, int, str]:
        """Where a statement ends last at the shallowest depth from `tail` on, outside every
        string, comment, template and regular expression; and, when the text ends inside one,
        where it opened and how. One pass over the characters that change state, never a mark
        list: the tokenizer read a template-heavy 17 MB bundle in 2,000 seconds."""
        depth, best, mode, opened, in_class = 0, None, "", -1, False
        resume: list[int] = []
        for match in Segments._SPECIAL.finditer(text):
            mark, at = match.group(), match.start()
            if mode == "":
                if mark in ('"', "'", "`", "//", "/*"):
                    mode, opened = mark, at
                elif mark == "/":
                    if Segments._REGEX_AFTER.search(text, max(0, at - 16), at):
                        mode, opened, in_class = "re", at, False
                elif mark in ("(", "[", "{", "${"):
                    depth += 1
                elif mark in (")", "]"):
                    depth -= 1
                elif mark == "}":
                    if resume and resume[-1] == depth:
                        resume.pop()
                        mode = "`"
                    else:
                        depth -= 1
                elif mark in (";", "\n") and at >= tail:
                    rank = (depth, 0 if mark == ";" else 1)
                    if best is None or rank <= best[0]:
                        best = (rank, at + 1)
            elif mode in ('"', "'"):
                if mark in (mode, "\n"):
                    mode = ""
            elif mode == "`":
                if mark == "`":
                    mode = ""
                elif mark == "${":
                    resume.append(depth)
                    mode = ""
            elif mode == "//":
                if mark == "\n":
                    mode = ""
            elif mode == "/*":
                if mark == "*/":
                    mode = ""
            elif mode == "re":
                if mark == "[":
                    in_class = True
                elif mark == "]":
                    in_class = False
                elif (mark == "/" and not in_class) or mark == "\n":
                    mode = ""
        return (best[1] if best is not None else None), (opened if mode else -1), mode

    @staticmethod
    def _closing(read: Read, at: int, size: int, until: str) -> int:
        """The offset of the first `until` from `at` not escaped by a backslash, or `size`."""
        delimiter = until.encode()
        quoted = until in "`'\""
        while at < size:
            chunk = read(at, Segments.SIZE + len(delimiter))
            if not chunk:
                break
            found = chunk.find(delimiter)
            while found >= 0:
                back = found - 1
                while quoted and back >= 0 and chunk[back] == 0x5C:
                    back -= 1
                if (found - 1 - back) % 2 == 0:
                    return at + found
                found = chunk.find(delimiter, found + 1)
            at += Segments.SIZE
        return size

    @staticmethod
    def _advance(read: Read, start: int, end: int, line: int, column: int) -> tuple[int, int]:
        at = start
        while at < end:
            chunk = read(at, min(Segments.SIZE, end - at))
            if not chunk:
                break
            newlines = chunk.count(b"\n")
            line += newlines
            column = len(chunk) - chunk.rfind(b"\n") - 1 if newlines else column + len(chunk)
            at += len(chunk)
        return line, column


class WholeFileCalls:
    """The calls of a large file, resolved once per file and shared by its pieces."""

    _cache: ClassVar[OrderedDict[int, tuple[Any, list[tuple[int, AstCall]]]]] = OrderedDict()
    KEPT: ClassVar[int] = 4

    @staticmethod
    def view(provider: Any, source: WindowSource, begin: int, raw: bytes) -> list[AstCall] | None:
        """The calls that start inside the piece `raw` at byte `begin`, placed in it; None when the
        piece is not the file's own bytes there (a file re-encoded to UTF-8 as it was read)."""
        try:
            sample = raw[:4096]
            with source.reader() as read:
                if read(begin, len(sample)) != sample:
                    return None
            located = WholeFileCalls._located(provider, source)
        except (OSError, WindowSourceChanged):  # not the file it was: the piece is parsed as is
            return None
        end = begin + len(raw)
        newlines, at = [], raw.find(b"\n")
        while at >= 0:
            newlines.append(at)
            at = raw.find(b"\n", at + 1)
        out: list[AstCall] = []
        first = bisect.bisect_left(located, begin, key=lambda item: item[0])
        for start, call in located[first:]:
            if start >= end:
                break
            offset = start - begin
            before = bisect.bisect_left(newlines, offset)
            column = offset - (newlines[before - 1] + 1 if before else 0)
            out.append(replace(call, line=before + 1, column=column))
        return out

    @staticmethod
    def _located(provider: Any, source: WindowSource) -> list[tuple[int, AstCall]]:
        cache = WholeFileCalls._cache
        key = ScanCaches.identity(source)
        held = cache.get(key)
        if held is not None and held[0] is source:
            cache.move_to_end(key)
            return held[1]
        with source.reader() as read:
            parts = (
                (segment.start, segment.line, segment.column, SegmentView(read, segment))
                for segment in Segments.of(read, source.size)
            )
            located = sorted(provider.resolve_parts(parts), key=lambda item: item[0])
        cache[key] = (source, located)
        while len(cache) > WholeFileCalls.KEPT:
            cache.popitem(last=False)
        return located


# Each source's calls, emptied after each scan with the other caches that hold a scan's files.
ScanCaches.register(WholeFileCalls._cache)

__all__ = ["Segment", "SegmentView", "Segments", "WholeFileCalls"]
