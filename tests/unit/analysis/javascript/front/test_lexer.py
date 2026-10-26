"""The tokens of a JavaScript source, from Cordon's own lexer."""

from __future__ import annotations

import random
import time

import pytest

from cordon_scanner.analysis.javascript.front.lexer import Lexer


class Lexed:
    @staticmethod
    def all(
        text: str, regex_after: frozenset[str] = frozenset({"(", "=", ",", ";", "return"})
    ) -> list[tuple[str, str]]:
        lexer, out, previous = Lexer(text), [], ""
        for _ in range(100_000):
            token = lexer.next(regex=previous in regex_after or previous == "")
            if token.kind == "eof":
                return out
            out.append((token.kind, token.value))
            previous = token.value
        raise AssertionError("the lexer did not reach the end")


class TestTokens:
    def test_names_numbers_and_punctuators(self) -> None:
        assert Lexed.all("a >>>= 0x1f_ff + 1e-3 ?? b?.c") == [
            ("name", "a"),
            ("punct", ">>>="),
            ("number", "0x1f_ff"),
            ("punct", "+"),
            ("number", "1e-3"),
            ("punct", "??"),
            ("name", "b"),
            ("punct", "?."),
            ("name", "c"),
        ]

    @pytest.mark.parametrize(
        "number", ["0", "1.5", ".5", "1_000", "0b1010", "0o17", "10n", "2E+10"]
    )
    def test_every_number_form(self, number: str) -> None:
        assert Lexed.all(number) == [("number", number)]

    def test_a_conditional_before_a_number_is_not_optional_chaining(self) -> None:
        assert ("punct", "?") in Lexed.all("a?.5:b")

    def test_strings_are_cooked(self) -> None:
        assert Lexed.all(r"'a\nb' " + '"\\x41\\u0042\\u{43}"') == [
            ("string", "a\nb"),
            ("string", "ABC"),
        ]

    def test_an_identifier_escape_is_decoded(self) -> None:
        assert Lexed.all(r"eval") == [("name", "eval")]

    def test_private_names(self) -> None:
        assert Lexed.all("this.#secret") == [
            ("name", "this"),
            ("punct", "."),
            ("private", "secret"),
        ]

    def test_comments_and_a_hashbang_are_trivia(self) -> None:
        assert Lexed.all("#!/usr/bin/env node\n// x\n/* y */ a") == [("name", "a")]


class TestTemplates:
    def test_a_template_without_substitutions_is_one_token(self) -> None:
        assert Lexed.all("`a b`") == [("template", "a b")]

    def test_substitutions_and_a_nested_object(self) -> None:
        assert Lexed.all("`a${ {b: 1}.b }c${d}e`") == [
            ("template_head", "a"),
            ("punct", "{"),
            ("name", "b"),
            ("punct", ":"),
            ("number", "1"),
            ("punct", "}"),
            ("punct", "."),
            ("name", "b"),
            ("template_middle", "c"),
            ("name", "d"),
            ("template_tail", "e"),
        ]

    def test_a_template_inside_a_substitution(self) -> None:
        kinds = [k for k, _ in Lexed.all("`x${`y${z}`}w`")]
        assert kinds == ["template_head", "template_head", "name", "template_tail", "template_tail"]


class TestRegex:
    def test_a_regex_where_an_operand_is_expected(self) -> None:
        assert ("regex", "/a[/]b/gi") in Lexed.all("x = /a[/]b/gi")

    def test_division_where_an_operator_is_expected(self) -> None:
        assert Lexed.all("a / b / c") == [
            ("name", "a"),
            ("punct", "/"),
            ("name", "b"),
            ("punct", "/"),
            ("name", "c"),
        ]


class TestLines:
    def test_a_line_break_is_marked_on_the_next_token(self) -> None:
        lexer = Lexer("a\nb /* \n */ c d")
        flags = [lexer.next().newline for _ in range(4)]
        assert flags == [False, True, True, False]

    def test_placement(self) -> None:
        lexer = Lexer("ab\ncd")
        assert (lexer.line_of(3), lexer.column_of(4)) == (2, 1)


class TestRecovery:
    def test_an_unterminated_string_is_an_error_and_lexing_goes_on(self) -> None:
        tokens = Lexed.all("'abc\nd")
        assert tokens[0][0] == "error" and tokens[-1] == ("name", "d")

    def test_random_input_always_terminates_without_an_exception(self) -> None:
        rng = random.Random(20261026)  # noqa: S311 -- a reproducible fuzz input, not a secret
        alphabet = "ab1 _$`'\"/\\{}()[];,.<>=!?:+-*&|^~#@\n\r\t${\u2028"
        for _ in range(300):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
            for regex in (True, False):
                lexer = Lexer(text)
                for _ in range(len(text) + 2):
                    token = lexer.next(regex=regex)
                    assert token.end >= token.start
                    if token.kind == "eof":
                        break
                else:
                    raise AssertionError("no progress")

    def test_time_is_linear_in_the_input(self) -> None:
        def seconds(n: int) -> float:
            """The best of five runs: on a loaded machine one run measures the machine."""
            text = "a = `x${b}y` + 'c' / d; // e\n" * n
            best = float("inf")
            for _ in range(5):
                lexer, started = Lexer(text), time.perf_counter()
                while lexer.next().kind != "eof":
                    pass
                best = min(best, time.perf_counter() - started)
            return best

        small, large = seconds(2_000), seconds(20_000)
        assert large < small * 25
