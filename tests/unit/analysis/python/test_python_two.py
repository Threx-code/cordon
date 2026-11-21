"""A file Python 3 refuses is said to be Python 2 only for a construct no Python 3 accepts, found on
the line the parse failed (`analysis/python/statements.py`'s PythonTwo, item 27)."""

from __future__ import annotations

import ast
import sys

import pytest

from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader
from cordon_scanner.analysis.python.statements import PythonTwo


class PythonTwoKit:
    @staticmethod
    def construct(text: str) -> str | None:
        try:
            ast.parse(text)
        except SyntaxError as exc:
            return PythonTwo.construct(text, exc.lineno)
        raise AssertionError("the fixture parses: it tests nothing")


class TestAPythonTwoConstruct:
    @pytest.mark.parametrize(
        ("text", "named"),
        [
            ('import os\nprint "building"\n', "a print statement"),
            ('exec "x = 1"\n', "an exec statement"),
            pytest.param(
                "try:\n    pass\nexcept ValueError, e:\n    pass\n",
                "except A, e",
                # PEP 758: Python 3.14 reads `except A, B:` as two exception types, so it parses.
                marks=pytest.mark.skipif(
                    sys.version_info >= (3, 14), reason="valid Python 3.14 (PEP 758)"
                ),
            ),
            # argweaver 0.8.1's setup.py, line 109 (item 27's count)
            (
                "def f():\n    raise DistutilsSetupError, \\\n        ('in libraries')\n",
                "raise E, value",
            ),
            ("if a <> b:\n    pass\n", "the <> operator"),
            ("x = ur'text'\n", "a ur'' string"),
            ("mode = 0777\n", "an octal literal written 0777"),
            ("x = `y`\n", "a backtick repr"),
        ],
    )
    def test_is_named(self, text: str, named: str) -> None:
        assert PythonTwoKit.construct(text) == named

    @pytest.mark.parametrize(
        "text",
        [
            # newer than this interpreter, or merely broken: Python 3 syntax errors, not Python 2
            "def f(:\n    pass\n",
            "x = t'{name}'\nprint(x\n",
            "match = [\n",
            "x = 00\ny = (\n",  # `00` is Python 3
            # a Python 2 construct on another line does not excuse this line's failure
            'def broken(:\n    pass\nprint "ok"\n',
        ],
    )
    def test_anything_else_is_not(self, text: str) -> None:
        assert PythonTwoKit.construct(text) is None

    def test_print_as_a_name_is_not_a_statement(self) -> None:
        text = "def f(print):\n    return print\nx = (\n"
        assert PythonTwoKit.construct(text) is None


class TestAWhollyPythonTwoFile:
    """A file is Python 2, and not merely a file holding one Python 2 token, only when every line the
    parse fails on is a Python-2-only construct (cordon-47's review of 09 3a)."""

    @pytest.mark.parametrize(
        "text",
        [
            'import os\nprint "building"\n',
            'try:\n    import x\nexcept ImportError, e:\n    print "no x", e\nraise ValueError, "m"\n',
            'def f(a):\n    if a <> 1:\n        exec "y = 2"\n    return `a`\n',
        ],
    )
    def test_python_2_through_and_through(self, text: str) -> None:
        assert PythonTwoReader.wholly(text)

    @pytest.mark.parametrize(
        "text",
        [
            # one Python 2 statement, then something no Python accepts
            'print "x"\ndef broken(:\n    pass\n',
            # one Python 2 statement hiding a line of garbage after it
            'print "x"\n\x00\x01 garbage (\n',
            # no Python 2 construct at all
            "def broken(:\n    pass\n",
            # a file that parses is not a Python 2 file
            "print('x')\n",
        ],
    )
    def test_anything_short_of_that_is_not(self, text: str) -> None:
        assert not PythonTwoReader.wholly(text)
