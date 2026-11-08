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

import pytest

from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader


class ReaderKit:
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
            ("try:\n    pass\nexcept ValueError, e:\n    pass\n", "except ValueError as e:"),
            ("try:\n    pass\nexcept ValueError,e:\n    pass\n", "except ValueError as e:"),
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
            ("try:\n    pass\nexcept IOError, (no, why):\n    pass\n", "except IOError:"),
            ("try:\n    pass\nexcept IOError as (no, why):\n    pass\n", "except IOError :"),
            ('p = "C:\\Users\\me"\nprint p\n', 'p = "C:\\\\Users\\\\me"'),
        ],
    )
    def test_each_construct_is_rewritten_to_what_it_means(self, source: str, kept: str) -> None:
        assert kept in ReaderKit.read(source)

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
