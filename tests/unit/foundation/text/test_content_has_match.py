"""`FileContent.has_match`: a pattern searched over the whole file the way `pattern.search(text)` would, without keeping the decoded text.

The parent holds a member's bytes, never its text (note 80: `text` for every member was 590 MB of 1.4 GB). The MCP server test used a 200,000-character
prefix read for that; a file padded before its import statement then looked like no server at all. Inert strings only: the import lines are the words of
an SDK import and nothing is run.
"""

from __future__ import annotations

import re

import pytest

from cordon_scanner.detect.agents.mcp_servers.source import ServerSources
from cordon_scanner.foundation.content import FileContent

IMPORT = b"from mcp.server.fastmcp import FastMCP\n"
FILLER = b"# padding that is a comment and nothing else, nothing in it to match\n"


class Padded:
    @staticmethod
    def before(count_bytes: int, tail: bytes) -> bytes:
        return FILLER * (count_bytes // len(FILLER)) + tail

    @staticmethod
    def around(left: int, middle: bytes, right: int) -> bytes:
        return FILLER * (left // len(FILLER)) + middle + FILLER * (right // len(FILLER))


class TestTheWholeFileIsSearched:
    def test_an_import_after_two_million_characters_is_found(self) -> None:
        content = FileContent.from_bytes("server.py", Padded.before(2_000_000, IMPORT))
        assert content.has_match(ServerSources.MCP_SDK_IMPORT)

    def test_no_import_is_none(self) -> None:
        assert not FileContent.from_bytes(
            "a.py", Padded.before(2_000_000, b"print(1)\n")
        ).has_match(ServerSources.MCP_SDK_IMPORT)

    def test_the_text_is_not_kept(self) -> None:
        content = FileContent.from_bytes("server.py", Padded.before(300_000, IMPORT))
        assert content.has_match(ServerSources.MCP_SDK_IMPORT)
        assert "text" not in content.__dict__

    def test_a_text_already_held_is_searched(self) -> None:
        content = FileContent.from_bytes("server.py", IMPORT)
        assert content.text.startswith("from mcp")
        assert content.has_match(ServerSources.MCP_SDK_IMPORT)

    def test_a_utf16_file_is_searched(self) -> None:
        raw = ("# padding\n" * 20_000 + IMPORT.decode()).encode("utf-16")
        assert FileContent.from_bytes("server.py", raw).has_match(ServerSources.MCP_SDK_IMPORT)


class TestAFileOverTheWholeLimitIsReadInStretches:
    """Each position the import line can take against a stretch's end: before it, across it, and after it (the stretch is 4 MiB, a file over 8 MiB)."""

    SIZE = FileContent.SEARCH_WHOLE + (1 << 20)

    @pytest.mark.parametrize(
        "left",
        [
            100,
            FileContent.SEARCH_STRETCH - 20,
            FileContent.SEARCH_STRETCH - 1,
            FileContent.SEARCH_STRETCH,
            FileContent.SEARCH_STRETCH + 5,
            SIZE - 100,
        ],
    )
    def test_the_import_at_each_position_is_found(self, left: int) -> None:
        raw = Padded.around(left, IMPORT, max(0, self.SIZE - left))
        assert len(raw) > FileContent.SEARCH_WHOLE
        assert FileContent.from_bytes("server.py", raw).has_match(ServerSources.MCP_SDK_IMPORT)

    def test_the_same_words_inside_a_long_line_are_not_a_line_start(self) -> None:
        # One 6 MiB line holds the import words in its middle: no line starts there, in one read or in stretches.
        line = b"x" * (3 << 20) + IMPORT.strip() + b"y" * (3 << 20) + b"\n"
        content = FileContent.from_bytes(
            "a.py", line + Padded.before(FileContent.SEARCH_WHOLE, b"")
        )
        assert len(content.raw) > FileContent.SEARCH_WHOLE
        assert not content.has_match(ServerSources.MCP_SDK_IMPORT)

    def test_a_match_running_over_the_cut_is_found(self) -> None:
        # The line starts a few bytes before the stretch's end and ends after it.
        raw = (
            Padded.before(FileContent.SEARCH_STRETCH - 10, b"")
            + IMPORT
            + Padded.before(self.SIZE, b"")
        )
        assert FileContent.from_bytes("server.py", raw).has_match(ServerSources.MCP_SDK_IMPORT)

    def test_it_agrees_with_the_whole_search_on_a_mixed_file(self) -> None:
        pattern = re.compile(r"^NEEDLE\d{1,3}$", re.MULTILINE)
        lines = [b"alpha\n", b"NEEDLE12\n", b"NEEDLE1234\n", b"xNEEDLE7\n", b"beta NEEDLE9\n"]
        for last in range(len(lines)):
            raw = (
                b"".join(lines[:last] or [b"\n"]) * 1
                + FILLER * ((FileContent.SEARCH_WHOLE + 4096) // len(FILLER))
                + lines[last]
            )
            whole = FileContent.from_bytes("a.txt", raw)
            expected = pattern.search(whole.text) is not None
            assert FileContent.from_bytes("a.txt", raw).has_match(pattern) is expected
