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

from cordon_scanner.foundation.text.comments import SourceComments


class CommentsHelpers:
    """Helpers for test_comments.py."""

    @staticmethod
    def spans(text: str, language: str = "javascript") -> tuple[tuple[int, int], ...]:
        return SourceComments.block_comment_spans(text, language)


class TestWhatCounts:
    def test_a_plain_block(self) -> None:
        text = "a /* b */ c"
        assert CommentsHelpers.spans(text) == ((2, 9),)
        assert text[2:9] == "/* b */"

    def test_several_blocks(self) -> None:
        assert CommentsHelpers.spans("/*a*/x/*b*/") == ((0, 5), (6, 11))

    def test_an_unterminated_block_runs_to_the_end(self) -> None:
        """Which is what a compiler would do with it."""
        assert CommentsHelpers.spans("code /* forever") == ((5, 15),)

    def test_a_language_without_block_comments_has_none(self) -> None:
        assert CommentsHelpers.spans("/* not a comment here */", "python") == ()


class TestWhatIsNotAComment:
    def test_a_block_opener_inside_a_string(self) -> None:
        assert CommentsHelpers.spans('const s = "/* not a comment */";') == ()

    def test_every_quote_style(self) -> None:
        for quote in ('"', "'", "`"):
            assert CommentsHelpers.spans(f"x = {quote}/*{quote}") == (), quote

    def test_a_block_opener_after_a_line_comment(self) -> None:
        assert CommentsHelpers.spans("// /* not opened\nreal();") == ()

    def test_an_escaped_quote_does_not_close_the_literal(self) -> None:
        r"""`"\"/*` is one string that never closes, not a string then a block.

        The escape is why this scan cannot be a search for the next quote.
        """
        assert CommentsHelpers.spans('"\\"/*') == ()

    def test_a_newline_closes_an_unterminated_literal(self) -> None:
        """So one stray quote does not swallow the rest of the file."""
        assert CommentsHelpers.spans('x = "oops\n/* real */') == ((10, 20),)

    def test_a_backslash_continues_the_literal_across_a_newline(self) -> None:
        """The escape consumes the newline, so the literal is still open and the
        `/*` on the next line is inside it -- which is what JavaScript does with
        a line continuation."""
        assert CommentsHelpers.spans('"a\\\n/* still a string */') == ()


class TestTheAnswerDoesNotDependOnWhoAsks:
    """It is cached, so it must be a pure function of its arguments."""

    def test_repeated_calls_agree(self) -> None:
        text = "/* a */ code /* b */"
        assert CommentsHelpers.spans(text) == CommentsHelpers.spans(text) == ((0, 7), (13, 20))

    def test_the_language_is_part_of_the_question(self) -> None:
        text = "# /* not in a C file */"
        assert CommentsHelpers.spans(text, "javascript") != CommentsHelpers.spans(text, "python")

    @pytest.mark.parametrize("language", ["javascript", "typescript", "java", "go", "rust", "c"])
    def test_every_block_comment_language_finds_one(self, language: str) -> None:
        assert CommentsHelpers.spans("/* x */", language) == ((0, 7),)


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
        found = CommentsHelpers.spans(text)
        assert all(0 <= start < end <= len(text) for start, end in found)
        assert all(a[1] <= b[0] for a, b in itertools.pairwise(found))


class TestCodeAfterABlockCommentCloses:
    """A line that closes a block comment is comment only to the close: the epxreso/epxresso npm
    campaign put its obfuscated payload after ` */` on the same line, and every rule read it as a
    remark (a MANGLED and PACKED miss)."""

    def test_a_continuation_line_is_comment(self) -> None:
        assert SourceComments.comment_column(" * Returns the value.", "javascript") == 0
        assert SourceComments.comment_column(" */", "javascript") == 0

    def test_code_after_the_close_is_code(self) -> None:
        line = " */ var _0xa000 = 0; eval(x);"
        assert not SourceComments.is_commented(line, line.index("eval"), "javascript")

    def test_a_comment_after_the_code_is_still_one(self) -> None:
        line = " */ run(); // eval(x)"
        assert SourceComments.is_commented(line, line.index("eval"), "javascript")
        assert not SourceComments.is_commented(line, line.index("run"), "javascript")

    def test_a_rule_reads_it(self, tmp_path) -> None:
        from cordon_scanner.detect.code.obfuscation.packing import PackingFindings
        from cordon_scanner.foundation.content import FileContent

        names = "".join(f"var _0x{0xA000 + i:04x} = 0;" for i in range(20))
        text = "/**\n * A library.\n " + "*/ " + names + "\n"
        content = FileContent.from_bytes("index.js", text.encode())
        ctx = type("Ctx", (), {"in_install_hook": staticmethod(lambda path: False)})()
        assert list(PackingFindings.mangled(content, ctx, "javascript"))  # type: ignore[arg-type]


class TestWhereTheExactSpansAreKnown:
    """The comment-reading audit (cordon-47, 2 Nov). With the file's exact block spans in hand, a line
    that starts with `*` is code unless a span holds it, and every comparison is in one unit."""

    @staticmethod
    def remark(text: str, needle: str) -> bool:
        from cordon_scanner.detect.code.obfuscation.encoding import EncodingFindings
        from cordon_scanner.foundation.content import FileContent

        content = FileContent.from_bytes("index.js", text.encode())
        return EncodingFindings.is_remark(
            content, text.encode().index(needle.encode()), "javascript"
        )

    @staticmethod
    def capability_comment(text: str, needle: str) -> bool:
        from cordon_scanner.detect.code.capability.text_position import TextPosition
        from cordon_scanner.foundation.content import FileContent

        content = FileContent.from_bytes("index.js", text.encode())
        return TextPosition.is_comment(content, text.encode().index(needle.encode()), "javascript")

    @pytest.mark.parametrize(
        "text",
        [
            "class A {\n  *gen() { eval(x); }\n}\n",
            "var z = 1\n  * eval(x);\n",
        ],
    )
    def test_a_line_starting_with_a_star_outside_a_block_is_code(self, text: str) -> None:
        assert not self.remark(text, "eval")
        assert not self.capability_comment(text, "eval")

    def test_a_continuation_line_inside_a_block_is_still_comment(self) -> None:
        text = "/**\n * eval(x) is documented here\n */\nrun();\n"
        assert self.remark(text, "eval")
        assert self.capability_comment(text, "eval")

    def test_multibyte_text_does_not_move_code_into_a_later_line_comment(self) -> None:
        text = 'const s = "' + "\u00e9" * 40 + '"; eval(x); // note\n'
        assert not self.remark(text, "eval")
        assert not self.capability_comment(text, "eval")
        assert self.remark(text, "note")

    def test_multibyte_text_does_not_move_code_into_a_later_block(self) -> None:
        text = 'const s = "' + "\u00e9" * 40 + '"; eval(x); /* a note */\n'
        assert not self.remark(text, "eval")
        assert not self.capability_comment(text, "eval")
        assert self.remark(text, "a note")


class TestTheIndexesAgreeWithThePlainReading:
    """`FileContent.byte_spans` and `in_block_comment` answer by bisect (item 71's cost fix): each
    must give exactly what an encode of the prefix and a scan of every span give, on random text."""

    ALPHABET = "a é€\U0001f600b\n/*x"

    @pytest.mark.parametrize("seed", range(40))
    def test_on_random_multiscript_text(self, seed: int) -> None:
        import random

        from cordon_scanner.foundation.content import FileContent

        rng = random.Random(seed)  # noqa: S311 - a fixed seed for test text, not a secret
        text = "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(1, 600)))
        raw = text.encode()
        content = FileContent.from_bytes("index.js", raw)
        spans = SourceComments.block_comment_spans(content.text, "javascript")
        expected = tuple((len(text[:s].encode()), len(text[:e].encode())) for s, e in spans)
        assert content.byte_spans(spans) == expected
        for offset in range(len(raw)):
            inside = any(start <= offset < end for start, end in expected)
            assert content.in_block_comment(offset, "javascript") is inside
