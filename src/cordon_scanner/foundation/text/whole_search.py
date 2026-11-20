"""A pattern searched over the whole of a file without keeping its decoded text.

The parent holds a member's bytes, never its text (note 80: `text` for every member was 590 MB of the parent's 1.4 GB). A prefix read of 200,000 characters
kept it down, and a file padded past it then hid its first match: the MCP server test saw no import statement and so no server. A file is decoded for the
length of one search, or in stretches when it is large; the search is the one `pattern.search(content.text)` makes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.text.encoding import TextEncoding

if TYPE_CHECKING:
    import re

    from cordon_scanner.foundation.content import FileContent


class WholeSearch:
    #: A file this size or smaller is decoded whole, for the length of one search; a larger one in stretches of `STRETCH` bytes.
    WHOLE: ClassVar[int] = 8 << 20
    STRETCH: ClassVar[int] = 4 << 20
    #: Past a stretch's end: the rest of a line (so none is cut) and the look-ahead a match may run into (a line start, then a few hundred characters).
    LINE_REACH: ClassVar[int] = 1 << 16
    LOOK_AHEAD: ClassVar[int] = 1 << 10

    @classmethod
    def has_match(cls, content: FileContent, pattern: re.Pattern[str]) -> bool:
        """Whether `pattern.search(content.text)` finds anything, anywhere in the file. A file over `WHOLE` is decoded in stretches that end at a line end;
        each is searched with a look-ahead and from the character after the one before it, so a line start (`^`) is a real one and a match running over
        the cut is found."""
        held = content.__dict__.get("text")
        if held is not None:
            return pattern.search(str(held)) is not None
        raw = content.raw
        if len(raw) <= cls.WHOLE or (
            raw.startswith((b"\xff\xfe", b"\xfe\xff")) and TextEncoding.looks_utf16(raw)
        ):
            return pattern.search(TextEncoding.decoded(raw, raw)) is not None
        start = 0
        while start < len(raw):
            end = min(len(raw), start + cls.STRETCH)
            if end < len(raw):
                newline = raw.find(b"\n", end, end + cls.LINE_REACH)
                end = newline + 1 if newline >= 0 else end
            lead = 1 if start else 0
            window = TextEncoding.decoded(raw, raw[start - lead : end + cls.LOOK_AHEAD])
            if pattern.search(window, lead) is not None:
                return True
            start = end
        return False


__all__ = ["WholeSearch"]
