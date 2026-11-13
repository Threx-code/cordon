"""A Python 2 file is read as code: rewritten, line for line, into Python 3 that parses
(`analysis/python/python_two_reader.py`, 09-UNKNOWN-CODE-READING 3a).

```
  print x · exec c in g · except A, e · raise E, v · 0L · 0777 · <> · `x` · ur'' · tabs
  tuple parameters · async/await as names · anything else Python 2 on the line -> neutralised
  a failure nothing explains -> no reading, and the line it stopped at
```
"""

from __future__ import annotations

import ast
import sys

import pytest

from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader


class ReaderKit:
    #: From Python 3.14 (PEP 758) `except A, B:` parses as a tuple of exceptions, so the
    #: Python 2 comma forms are code there and no reading is asked of the reader.
    COMMA_PARSES = pytest.mark.skipif(
        sys.version_info >= (3, 14), reason="PEP 758: `except A, B:` parses on this Python"
    )

    @staticmethod
    def read(text: str) -> str:
        try:
            ast.parse(text)
        except SyntaxError:
            pass
        else:
            raise AssertionError("the fixture parses: it tests nothing")
        reading = PythonTwoReader.read(text)
        assert reading.text is not None, reading
        ast.parse(reading.text)
        assert reading.text.count("\n") == text.count("\n"), "line numbers moved"
        return reading.text


class TestAPythonTwoFileIsReadAsCode:
    @pytest.mark.parametrize(
        ("source", "kept"),
        [
            ('import os\nprint "x", os.name\n', 'print("x", os.name)'),
            ("import sys\nprint >>sys.stderr, 'x'\nprint 'y'\n", "print(sys.stderr, 'x')"),
            ("code = 'x = 1'\nexec code in globals()\n", "exec(code , globals())"),
            pytest.param(
                "try:\n    pass\nexcept ValueError, e:\n    pass\n",
                "except ValueError as e:",
                marks=ReaderKit.COMMA_PARSES,
            ),
            pytest.param(
                "try:\n    pass\nexcept ValueError,e:\n    pass\n",
                "except ValueError as e:",
                marks=ReaderKit.COMMA_PARSES,
            ),
            ("raise ValueError, 'bad'\n", "raise ValueError( 'bad')"),
            ("x = 0L + 0xFFL\n", "x = 0 + 0xFF"),
            ("mode = 0777\n", "mode = 0o777"),
            ("if 1 <> 2:\n    pass\n", "if 1 != 2:"),
            ("s = `1`\n", "s = repr(1)"),
            ("s = ur'a'\n", "s = r'a'"),
            ("if x: print 'y'\n", "if x: print('y')"),
            ("def f(self, (a, b)):\n    return a\n", "def f(self, a, b):"),
            ("f = lambda (x, y): x\n", "f = lambda x, y: x"),
            ("import asyncio\nasyncio.async(f())\n", "asyncio.async_(f())"),
            ("def async(n):\n    return n\n", "def async_(n):"),
            ("async = True\nif async:\n    pass\n", "if async_:"),
            ("async = f('x')\nif async is None:\n    pass\n", "if async_ is None:"),
            ("def f(async):\n    return async or 1\n", "return async_ or 1"),
            ("def f(async):\n    if not async and 1:\n        pass\n", "if not async_ and 1:"),
            ("def f(async):\n    return async\n", "return async_"),
            ("def f(a):\n    return a.None\n", "return a.None_"),
            # Python 3.13: a default for a type parameter. This Python does not parse it; the
            # default is code, so it is kept, on its line, as a bound.
            ("class Box[T = int]:\n    x = 1\n", "class Box[T: (int)]:"),
            (
                "def first[T: str = str, *Ts = *tuple[int]](a):\n    return a\n",
                "def first[T: (str, str), Ts: (*tuple[int],)](a):",
            ),
            pytest.param(
                "try:\n    pass\nexcept IOError, (no, why):\n    pass\n",
                "except IOError:",
                marks=ReaderKit.COMMA_PARSES,
            ),
            ("try:\n    pass\nexcept IOError as (no, why):\n    pass\n", "except IOError :"),
            ('p = "C:\\Users\\me"\nprint p\n', 'p = "C:\\\\Users\\\\me"'),
        ],
    )
    def test_each_construct_is_rewritten_to_what_it_means(self, source: str, kept: str) -> None:
        assert kept in ReaderKit.read(source)

    @pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax parses from 3.12")
    @pytest.mark.skipif(sys.version_info >= (3, 13), reason="3.13 parses a type default itself")
    @pytest.mark.parametrize(
        "source",
        [
            "import os\ndef first[T = os.getcwd()](a):\n    return a\n",
            "import os\nclass Box[T: object = os.getcwd()]:\n    pass\n",
            "import os\ntype Alias[*Ts = *os.environ] = tuple[*Ts]\n",
        ],
    )
    def test_a_type_default_is_code_and_stays_in_the_tree(self, source: str) -> None:
        """The default is evaluated when it is read, so a call in it is a call the analysers see."""
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(ast.parse(ReaderKit.read(source)))
            if isinstance(node, ast.Call)
        } | {
            ast.unparse(node)
            for node in ast.walk(ast.parse(ReaderKit.read(source)))
            if isinstance(node, ast.Attribute)
        }
        assert "os.getcwd" in calls or "os.environ" in calls

    def test_tabs_in_indentation_count_eight_columns_as_python_2_did(self) -> None:
        source = "def f():\n        x = 1\n\treturn x\n"
        assert "        return x" in ReaderKit.read(source)

    def test_a_string_holding_python_2_text_is_left_alone(self) -> None:
        source = "s = 'print \"x\" <> 0777L'\nprint s\n"
        assert "'print \"x\" <> 0777L'" in ReaderKit.read(source)

    def test_a_statement_over_several_lines_is_rewritten_whole(self) -> None:
        source = 'print "a", \\\n    "b"\nprint ("c",\n       "d"), "e"\nx = 1\n'
        text = ReaderKit.read(source)
        assert text.splitlines()[-1] == "x = 1"

    def test_a_str_keeps_the_value_python_2_gave_it(self) -> None:
        # In a Python 2 str, `\U`, `\N` and `\u` are not escapes: the backslash is kept.
        source = 'a = "C:\\Users\\N\\u00e9"\nb = u"\\u00e9"\nc = b"\\U"\nprint a\n'
        tree = ast.parse(ReaderKit.read(source))
        values = [node.value.value for node in tree.body[:3]]  # type: ignore[attr-defined]
        assert values == ["C:\\Users\\N\\u00e9", "\u00e9", b"\\U"]

    def test_unicode_literals_keeps_the_escapes(self) -> None:
        source = 'from __future__ import unicode_literals\na = "\\u00e9"\nprint a\n'
        tree = ast.parse(ReaderKit.read(source))
        assert tree.body[1].value.value == "\u00e9"  # type: ignore[attr-defined]

    def test_the_acts_stay_in_the_reading(self) -> None:
        source = "import os\nprint 'go'\nos.system('id')\n"
        assert "os.system('id')" in ReaderKit.read(source)

    @pytest.mark.parametrize(
        "separator", ["\x0c", "\x0b", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
    )
    def test_a_character_str_splitlines_breaks_on_moves_no_rewrite(self, separator: str) -> None:
        # str.splitlines breaks a line at a form feed (and these others); Python's tokenizer does
        # not. Split that way, each rewrite after it landed one line early: lava-test 0.14's
        # commands.py (a form feed in a docstring) came out as `def invok((self):` (S2 probe).
        source = f'class A:\n    """one{separator}two"""\n\n    def f(self):\n        print "x"\n'
        text = ReaderKit.read(source)
        assert "    def f(self):\n" in text and 'print("x")' in text


class TestANeutralisedStatementKeepsItsLines:
    """A statement the reader makes inert keeps its line's own ending, so the reading has the file's
    line count (tests/fuzz/test_code_parsers.py found a lone backquote read as `pass\\n`)."""

    @pytest.mark.parametrize(
        "source",
        ["`", "a`", "`\n", "print 'x'\n`", "x = 1\r\n`\r\ny = 2", "if a:\n    `", "f(1,\n  `)"],
    )
    def test_the_line_count_is_the_file_s(self, source: str) -> None:
        reading = PythonTwoReader.read(source)
        assert reading.text is not None
        assert reading.text.count("\n") == source.count("\n")

    def test_a_line_ending_is_kept_as_written(self) -> None:
        reading = PythonTwoReader.read("x = 1\r\n`\r\ny = 2\r\n")
        assert reading.text == "x = 1\r\npass\r\ny = 2\r\n"


class TestWhatIsNotPythonTwo:
    def test_garbage_is_not_read_and_the_line_is_named(self) -> None:
        reading = PythonTwoReader.read('print "x"\ndef run(:\n    pass\n')
        assert reading.text is None
        assert reading.stuck_line == 2

    def test_a_file_padded_past_the_bound_names_no_line(self) -> None:
        line = "def f%d(a, (b, c)): pass\n"
        source = "".join(line % i for i in range(PythonTwoReader.RETRIES + 5))
        reading = PythonTwoReader.read(source)
        assert reading.text is None
        assert reading.stuck_line is None


class TestWhollyNeutralisesTheWholeStatement:
    def test_a_print_over_two_lines_is_still_wholly_python_2(self) -> None:
        source = 'import x\nprint "a %s" % \\\n    x.y\n'
        assert PythonTwoReader.wholly(source)


class TestTheLineCountOfWhatItReads:
    """What the reader gives back stands where the file had it, line for line: every finding's line
    number comes from it. A last line with no line ending stays without one when it is made inert."""

    @staticmethod
    def breaks(text: str) -> int:
        return text.count("\n") + text.count("\r")

    @pytest.mark.parametrize(
        "source",
        ["print x \\", "import a\nprint x", "print x\r\nprint y \\"],
    )
    def test_the_text_has_as_many_lines_as_the_file(self, source: str) -> None:
        reading = PythonTwoReader.read(source)
        assert reading.text is not None
        assert self.breaks(reading.text) == self.breaks(source)
