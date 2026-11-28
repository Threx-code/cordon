"""The Python 2 reader on text it cannot make Python 3, and its small scanners for quotes, brackets, comments and defaults (`analysis/python/python_two_reader.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader


class TestReading:
    def test_text_that_is_not_python_two_either_is_not_read(self) -> None:
        assert PythonTwoReader.read("def f(:\n").text is None

    def test_text_the_parser_refuses_with_a_value_error_is_not_read(self) -> None:
        assert PythonTwoReader.read("x = 1\x00\n").text is None
        assert PythonTwoReader.wholly("x = 1\x00\n") is False

    def test_a_file_with_no_python_two_construct_on_its_failing_line_is_not_wholly_python_two(self) -> None:
        assert PythonTwoReader.wholly("def f(:\n") is False

    def test_a_print_statement_file_is_read_as_python_two(self) -> None:
        assert PythonTwoReader.wholly("print 'hello'\n") is True


class TestScanners:
    def test_an_unterminated_string_ends_at_its_line(self) -> None:
        assert PythonTwoReader._string_end("'abc\nnext", 0) == 4
        assert PythonTwoReader._string_end("'abc", 0) == 4

    def test_a_statement_across_lines_is_left_as_it_is(self) -> None:
        lines = ["x = foo(1,\n", "        2)\n"]
        assert PythonTwoReader.statements(list(lines)) == lines

    def test_bracket_depth_skips_comments_and_strings(self) -> None:
        lines = ["x = (1,  # ( not a bracket\n", "     '(' )\n", "y = 2\n"]
        assert PythonTwoReader._depths(lines) == [0, 1, 0, 0]

    @pytest.mark.parametrize(
        ("part", "expected"),
        [
            ("T = int", 2),
            ("name", None),
            ("T: tuple = (1, 2)", 9),
            ("T = 'a=b'", 2),
            ("T == U", None),
            ("f(a=1)", None),
        ],
    )
    def test_the_equals_that_starts_a_default_is_found_outside_quotes_and_brackets(
        self, part: str, expected: int | None
    ) -> None:
        found = PythonTwoReader.default_equals(part)
        assert found == expected

    def test_a_type_parameter_default_is_kept_in_a_bound(self) -> None:
        kept = PythonTwoReader.with_type_defaults_kept("def f[T = int, U: str = str](x): pass\n")
        assert "T: (int)" in kept or "T: int" in kept
        assert "U: (str, str)" in kept

    def test_a_definition_with_no_type_parameter_list_or_one_that_never_closes_is_left_alone(self) -> None:
        line = "def f(x): pass\n"
        assert PythonTwoReader.with_type_defaults_kept(line) == line
        open_ended = "def f[T = int(x): pass\n"
        assert PythonTwoReader.with_type_defaults_kept(open_ended) == open_ended


class TestMoreShapes:
    def test_a_default_after_a_quoted_bound_is_still_found(self) -> None:
        assert PythonTwoReader.default_equals("T: 'a=b' = 1") == 9

    def test_a_type_parameter_list_with_a_quoted_default_and_one_without_a_default(self) -> None:
        kept = PythonTwoReader.with_type_defaults_kept("def f[T, U = 'x'](a): pass\n")
        assert "T" in kept and "U: ('x')" in kept or "U: 'x'" in kept

    def test_a_print_statement_across_lines_becomes_one_call_across_the_same_lines(self) -> None:
        lines = ["print foo(1,\n", "         2)\n"]
        assert PythonTwoReader.statements(list(lines)) == ["print(foo(1,\n", "         2))\n"]

    def test_a_default_that_is_not_a_name_keeps_the_line_as_written(self) -> None:
        line = "def f[1 = int](a): pass\n"
        assert PythonTwoReader.with_type_defaults_kept(line) == line
