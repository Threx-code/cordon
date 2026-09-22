"""Where a block comment starts and stops.

Three detectors ask this question about every file they read, and a wrong answer
is not a cosmetic problem in either direction: a span that is too long hides real
code from the capability and secret rules, and one that is too short reports
prose as a credential.

The scan was rewritten from a character-by-character walk into one that jumps
between interesting positions, which is eleven times faster and has to be
exactly as correct. These are the cases that distinguish the two.
"""

from __future__ import annotations

import itertools

import pytest

from cordon_scanner.core.comments import block_comment_spans


def spans(text: str, language: str = "javascript") -> tuple[tuple[int, int], ...]:
    return block_comment_spans(text, language)


class TestWhatCounts:
    def test_a_plain_block(self) -> None:
        text = "a /* b */ c"
        assert spans(text) == ((2, 9),)
        assert text[2:9] == "/* b */"

    def test_several_blocks(self) -> None:
        assert spans("/*a*/x/*b*/") == ((0, 5), (6, 11))

    def test_an_unterminated_block_runs_to_the_end(self) -> None:
        """Which is what a compiler would do with it."""
        assert spans("code /* forever") == ((5, 15),)

    def test_a_language_without_block_comments_has_none(self) -> None:
        assert spans("/* not a comment here */", "python") == ()


class TestWhatIsNotAComment:
    def test_a_block_opener_inside_a_string(self) -> None:
        assert spans('const s = "/* not a comment */";') == ()

    def test_every_quote_style(self) -> None:
        for quote in ('"', "'", "`"):
            assert spans(f"x = {quote}/*{quote}") == (), quote

    def test_a_block_opener_after_a_line_comment(self) -> None:
        assert spans("// /* not opened\nreal();") == ()

    def test_an_escaped_quote_does_not_close_the_literal(self) -> None:
        r"""`"\"/*` is one string that never closes, not a string then a block.

        The escape is why this scan cannot be a search for the next quote.
        """
        assert spans('"\\"/*') == ()

    def test_a_newline_closes_an_unterminated_literal(self) -> None:
        """So one stray quote does not swallow the rest of the file."""
        assert spans('x = "oops\n/* real */') == ((10, 20),)

    def test_a_backslash_continues_the_literal_across_a_newline(self) -> None:
        """The escape consumes the newline, so the literal is still open and the
        `/*` on the next line is inside it -- which is what JavaScript does with
        a line continuation."""
        assert spans('"a\\\n/* still a string */') == ()


class TestTheAnswerDoesNotDependOnWhoAsks:
    """It is cached, so it must be a pure function of its arguments."""

    def test_repeated_calls_agree(self) -> None:
        text = "/* a */ code /* b */"
        assert spans(text) == spans(text) == ((0, 7), (13, 20))

    def test_the_language_is_part_of_the_question(self) -> None:
        text = "# /* not in a C file */"
        assert spans(text, "javascript") != spans(text, "python")

    @pytest.mark.parametrize("language", ["javascript", "typescript", "java", "go", "rust", "c"])
    def test_every_block_comment_language_finds_one(self, language: str) -> None:
        assert spans("/* x */", language) == ((0, 7),)


class TestSpansAreWellFormed:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "/*",
            "*/",
            "/*/",
            "/**/",
            '"/*" /* real */',
            "// /*\n/* real */",
            "/* one */ /* two */",
            "`${'/*'}` /* real */",
        ],
    )
    def test_they_are_ordered_disjoint_and_inside_the_text(self, text: str) -> None:
        found = spans(text)
        assert all(0 <= start < end <= len(text) for start, end in found)
        assert all(a[1] <= b[0] for a, b in itertools.pairwise(found))
