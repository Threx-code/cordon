"""`TextSegments`: a pattern read over a whole text a segment at a time gives what the whole read gives.

Inert strings only: nothing here is a file, a sample or a payload.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from cordon_scanner.foundation.text.segments import OVERLAP_CHARS, SEGMENT_CHARS, TextSegments

if TYPE_CHECKING:
    from collections.abc import Iterable
    from re import Match

NEEDLE = re.compile(r"needle\d{0,3}")
"""The longest match is nine characters."""
LONGEST = 9


def spans(matches: Iterable[Match[str]]) -> list[tuple[int, int]]:
    return [m.span() for m in matches]


class TestTheSameMatchesAsTheWholeRead:
    @pytest.mark.parametrize("position", range(140))
    def test_a_match_at_any_position_is_found_once(self, position: int) -> None:
        text = "-" * position + "needle123" + "-" * (140 - position)
        found = spans(TextSegments.finditer(NEEDLE, text, size=16, overlap=LONGEST))
        assert found == spans(NEEDLE.finditer(text)) == [(position, position + 9)]

    @pytest.mark.parametrize(("size", "overlap"), [(7, 9), (16, 9), (25, 12), (64, 9), (1000, 9)])
    def test_many_matches_are_the_whole_reads_matches(self, size: int, overlap: int) -> None:
        text = "".join(f"needle{n % 1000} --- " for n in range(90))
        assert spans(TextSegments.finditer(NEEDLE, text, size=size, overlap=overlap)) == spans(
            NEEDLE.finditer(text)
        )

    def test_matches_that_touch_are_each_found(self) -> None:
        text = "needle1" * 60
        assert spans(TextSegments.finditer(NEEDLE, text, size=10, overlap=LONGEST)) == spans(
            NEEDLE.finditer(text)
        )

    def test_a_line_start_at_the_edge_of_a_segment_is_still_a_line_start(self) -> None:
        # `^` and `$` see the real line, not the start or end of the piece being read.
        lines = re.compile(r"^a$", re.MULTILINE)
        text = "a\nab\n" * 40
        found = spans(TextSegments.finditer(lines, text, size=7, overlap=2))
        assert found == spans(lines.finditer(text))
        assert len(found) == 40

    def test_a_word_edge_at_the_edge_of_a_segment_is_still_a_word_edge(self) -> None:
        word = re.compile(r"\bcat\b")
        text = "concatenate cat scatter cat " * 30
        for size in range(5, 40):
            assert spans(TextSegments.finditer(word, text, size=size, overlap=3)) == spans(
                word.finditer(text)
            )

    def test_the_first_match_is_the_whole_reads_first_match(self) -> None:
        text = "-" * 500 + "needle7" + "-" * 500 + "needle8"
        found = TextSegments.search(NEEDLE, text, size=64, overlap=LONGEST)
        assert found is not None
        assert found.span() == NEEDLE.search(text).span()  # type: ignore[union-attr]

    def test_a_text_without_a_match_has_no_match(self) -> None:
        assert TextSegments.search(NEEDLE, "-" * 5000, size=64, overlap=LONGEST) is None
        assert list(TextSegments.finditer(NEEDLE, "", size=64, overlap=LONGEST)) == []


class TestThePastOfTheOldCap:
    """The cap the readers had was a million characters: a match after it is a match."""

    def test_a_match_past_a_million_characters_is_found_at_the_default_sizes(self) -> None:
        padding = "-" * (SEGMENT_CHARS + 5000)
        text = padding + "needle42" + "-" * 100
        found = TextSegments.search(NEEDLE, text)
        assert found is not None
        assert found.start() == len(padding)

    def test_a_match_across_the_end_of_the_first_million_characters_is_found(self) -> None:
        text = "-" * (SEGMENT_CHARS - 4) + "needle123" + "-" * 100
        found = TextSegments.search(NEEDLE, text)
        assert found is not None
        assert found.span() == (SEGMENT_CHARS - 4, SEGMENT_CHARS + 5)


class Recorder:
    """A pattern that notes the stretch every call was asked to read."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern
        self.calls: list[tuple[int, int]] = []

    def finditer(self, text: str, pos: int = 0, endpos: int | None = None) -> object:
        end = len(text) if endpos is None else min(endpos, len(text))
        self.calls.append((pos, end))
        return self.pattern.finditer(text, pos, end)


class TestEachStepIsBounded:
    def test_no_call_reads_more_than_a_segment_and_its_overlap(self) -> None:
        recorder = Recorder(NEEDLE)
        text = "".join(f"needle{n} ---- " for n in range(400))
        list(TextSegments.finditer(recorder, text, size=100, overlap=20))  # type: ignore[arg-type]
        assert len(recorder.calls) > 10
        assert all(end - pos <= 120 for pos, end in recorder.calls)

    def test_the_steps_cover_the_whole_text(self) -> None:
        recorder = Recorder(NEEDLE)
        text = "-" * 1000
        list(TextSegments.finditer(recorder, text, size=100, overlap=20))  # type: ignore[arg-type]
        assert recorder.calls[0][0] == 0
        assert recorder.calls[-1][1] == len(text)
        starts = [pos for pos, _ in recorder.calls]
        assert starts == sorted(starts)

    def test_a_short_text_is_read_in_one_call(self) -> None:
        recorder = Recorder(NEEDLE)
        list(TextSegments.finditer(recorder, "needle1", size=100, overlap=20))  # type: ignore[arg-type]
        assert len(recorder.calls) == 1


class TestTheSizes:
    def test_the_overlap_is_the_engines_window_overlap(self) -> None:
        from cordon_scanner.foundation.files.windows import OVERLAP

        assert OVERLAP_CHARS == OVERLAP

    @pytest.mark.parametrize(("size", "overlap"), [(0, 5), (-1, 5), (10, -1)])
    def test_a_segment_needs_a_positive_size_and_a_non_negative_overlap(
        self, size: int, overlap: int
    ) -> None:
        with pytest.raises(ValueError, match="positive size"):
            list(TextSegments.finditer(NEEDLE, "needle", size=size, overlap=overlap))
