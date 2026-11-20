"""Columns and offsets in characters for a file's bytes, so a comparison is never bytes against
characters (item 71: a byte column measured against a character column read code as comment).

Every answer is bounded: an ASCII file takes the identity; a non-ASCII line keeps checkpoints of its
continuation bytes every `_STRIDE` bytes, made once, so a look-up is a bisect plus at most one stride
(a 10 MB line of 263,157 block comments is the killer suite's multibyte-blocks probe).
"""

from __future__ import annotations

from array import array
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent, LineIndex

#: Every byte that is not a UTF-8 continuation byte (`translate` deletes these, leaving the
#: continuations to count), and the stride of `char_column`'s per-line checkpoints.
_NOT_CONTINUATION = bytes(b for b in range(256) if not 0x80 <= b <= 0xBF)
_STRIDE = 64
#: The UTF-8 byte-order mark, which `TextEncoding.decoded` reads past.
_UTF8_MARK = b"\xef\xbb\xbf"


class TextColumns:
    """The character-column answers `LineIndex` and `FileContent` give, worked out here."""

    @staticmethod
    def char_column(index: LineIndex, byte_offset: int) -> int:
        """0-indexed column, in characters, of an offset within its line: the unit
        `SourceComments.comment_column` answers in, so a comparison is never bytes against
        characters (a run of multibyte text early on a line moved a byte column past a later `//`
        and read the code before it as a comment)."""
        offset = index.placed(byte_offset)
        line = index.line_of(offset, place=False)
        start = index.line_starts[line - 1]
        if index._ascii:
            return offset - start
        # Characters are the bytes that are not UTF-8 continuation bytes. Counted from checkpoints
        # made once per line (every `_STRIDE` bytes, so a 10 MB line holds 160 k of them), plus at
        # most one stride counted per call: a bundle's one long line is one pass, not one decode
        # per match.
        checkpoints = TextColumns._checkpoints(index, line)
        block = (offset - start) // _STRIDE
        base = start + block * _STRIDE
        continued = checkpoints[block] + len(
            index.raw[base:offset].translate(None, _NOT_CONTINUATION)
        )
        return (offset - start) - continued

    @staticmethod
    def byte_spans(
        index: LineIndex, spans: tuple[tuple[int, int], ...]
    ) -> tuple[tuple[int, int], ...]:
        """Spans over the decoded text (`block_comment_spans`, docstrings, test modules) as byte
        spans, so a match's byte offset is compared in its own unit. Equal to `spans` in an ASCII
        file; in one with multibyte text the character spans sit earlier than the bytes they cover."""
        if index._ascii:
            return spans  # characters and bytes agree
        # The decoded text has no byte-order mark (it is decoded past one), and the per-line character
        # starts count it as the first line's first character: one character on, in the same frame.
        mark = 1 if index.raw.startswith(_UTF8_MARK) else 0
        return tuple(
            (TextColumns._byte_of(index, start + mark), TextColumns._byte_of(index, end + mark))
            for start, end in spans
        )

    @staticmethod
    def byte_offset(index: LineIndex, char_offset: int, text: str) -> int:
        """The byte offset in the file of a character offset in `text`.

        In the file's own decoded text (`FileContent.text`) that is every byte before it, a UTF-8
        byte-order mark included: the text is decoded past the mark, so re-encoding the text before the
        offset came out three bytes short in every file saved with one, and each finding placed that
        way sat three bytes early -- its column off and its evidence three bytes of the code before
        it. Any other string is re-encoded as it always was."""
        before = len(text[:char_offset].encode("utf-8"))
        if index.__dict__.get("text") is text and index.raw.startswith(_UTF8_MARK):
            return before + len(_UTF8_MARK)
        return before

    @staticmethod
    def _checkpoints(index: LineIndex, line: int) -> array[int]:
        """Continuation bytes counted at every `_STRIDE` bytes of a line, made once per line."""
        key = ("continuation", line)
        checkpoints = index._per_line.get(key)
        if checkpoints is None:
            start, stop = index.line_starts[line - 1], TextColumns._line_stop(index, line)
            checkpoints, total = array("I"), 0
            for at in range(start, stop + 1, _STRIDE):
                checkpoints.append(total)
                block = index.raw[at : min(at + _STRIDE, stop)]
                total += len(block.translate(None, _NOT_CONTINUATION))
            index._per_line[key] = checkpoints
        return checkpoints

    @staticmethod
    def _line_stop(index: LineIndex, line: int) -> int:
        """The byte offset where a line ends, its newline excluded: from `line_starts`, never a
        search (a `find` per call scanned a 10 MB line to its end each time)."""
        if line < len(index.line_starts):
            return index.line_starts[line] - 1
        return len(index.raw)

    @staticmethod
    def _byte_of(index: LineIndex, char_offset: int) -> int:
        """The byte offset of a character offset: its line by bisect, its stride by bisect over the
        line's checkpoints, then at most one stride walked (never a decode of the line)."""
        from bisect import bisect_right

        starts = index._line_char_starts
        line = max(1, bisect_right(starts, char_offset))
        within = char_offset - starts[line - 1]
        first = index.line_starts[line - 1]
        stop = TextColumns._line_stop(index, line)
        checkpoints = TextColumns._checkpoints(index, line)
        # Characters before stride k: k * _STRIDE bytes less the continuations among them.
        low, high = 0, len(checkpoints) - 1
        while low < high:
            mid = (low + high + 1) // 2
            if mid * _STRIDE - checkpoints[mid] <= within:
                low = mid
            else:
                high = mid - 1
        at, chars = first + low * _STRIDE, low * _STRIDE - checkpoints[low]
        # A stride can start inside a character: its continuation bytes were counted with it.
        while at < stop and 0x80 <= index.raw[at] <= 0xBF:
            at += 1
        while at < stop and chars < within:
            at += 1
            while at < stop and 0x80 <= index.raw[at] <= 0xBF:
                at += 1
            chars += 1
        return at + max(0, within - chars)

    @staticmethod
    def in_block_comment(content: FileContent, byte_offset: int, language: str | None) -> bool:
        """Whether a byte offset lies in one of the file's `/* ... */` blocks: the exact spans
        (`SourceComments.block_comment_spans`), in bytes, indexed once per file and asked by bisect,
        so a file of 200,000 blocks costs one pass, not a scan of every span per match."""
        from bisect import bisect_right

        key = (f"blocks:{language}", -1)
        found = content._per_line.get(key)
        if found is None:
            from cordon_scanner.foundation.text.comments import SourceComments

            spans = TextColumns.byte_spans(
                content, SourceComments.block_comment_spans(content.text, language)
            )
            found = ([start for start, _ in spans], [end for _, end in spans])
            content._per_line[key] = found
        starts, ends = found
        at = bisect_right(starts, byte_offset) - 1
        return bool(at >= 0 and byte_offset < ends[at])


__all__ = ["TextColumns"]
