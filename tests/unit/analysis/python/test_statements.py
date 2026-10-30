"""A module too large to parse at once is parsed a run of whole top-level statements at a time (D1).

`PythonStatements.starts` finds where each top-level statement starts; every run of whole
statements from one start to another must parse on its own, a decorator stays with what it
decorates, and `else`/`except`/`elif`/`finally` stay with the statement they continue. Finding the
starts is one pass of the tokenizer, so its time grows with the module, not faster.
"""

from __future__ import annotations

import ast
import time

from cordon_scanner.analysis.python.statements import PythonStatements

SOURCE = '''import os
x = 1

class A:
    a = 1

    def f(self):
        return 2


@deco
class B:
    """doc
not a statement
"""
    b = (1,
2)
y = [
 3]
if x:
    z = 1
else:
    z = 2
def g():
    pass
try:
    pass
except E:
    pass
else:
    pass
finally:
    pass
if a:
    pass
elif b:
    pass
@a
@b(1)
def h():
    pass
w = 4
'''


class TestPythonStatements:
    @staticmethod
    def heads(source: str) -> list[str]:
        return [source[at:].split("\n", 1)[0] for at in PythonStatements.starts(source)]

    @staticmethod
    def module(statements: int) -> str:
        """A generated module of `statements` classes, each with a decorated method."""
        return "".join(
            f"class C{n}:\n    @property\n    def v(self):\n        return {n}\n\n"
            for n in range(statements)
        )

    def test_every_top_level_statement_starts_a_run(self) -> None:
        assert self.heads(SOURCE) == [
            "import os",
            "x = 1",
            "class A:",
            "@deco",
            "y = [",
            "if x:",
            "def g():",
            "try:",
            "if a:",
            "@a",
            "w = 4",
        ]

    def test_every_run_of_whole_statements_parses(self) -> None:
        starts = [*PythonStatements.starts(SOURCE), len(SOURCE)]
        for i in range(len(starts) - 1):
            for j in range(i + 1, len(starts)):
                ast.parse(SOURCE[starts[i] : starts[j]])

    def test_a_text_that_stops_inside_a_statement_keeps_the_starts_before(self) -> None:
        cut = SOURCE.index("not a statement")  # inside B's docstring
        assert self.heads(SOURCE[:cut]) == ["import os", "x = 1", "class A:", "@deco"]

    def test_the_last_cut_is_a_byte_offset_past_text_that_is_not_ascii(self) -> None:
        data = 'é = "ü"\nclass A:\n    pass\nb = 1\n'.encode()
        at = PythonStatements.last_cut(data)
        assert data[at:] == b"b = 1\n"
        ast.parse(data[:at].decode())

    def test_one_statement_cannot_be_cut(self) -> None:
        assert PythonStatements.last_cut(b"x = [\n1,\n2]\n") == 0

    def test_its_time_grows_with_the_module_not_faster(self) -> None:
        small, large = self.module(2_000), self.module(8_000)

        def cpu(source: str) -> float:
            best = float("inf")
            for _ in range(3):
                started = time.process_time()
                PythonStatements.starts(source)
                best = min(best, time.process_time() - started)
            return best

        assert len(PythonStatements.starts(large)) == 8_000
        # Four times the statements: about four times the time. A pass that grew with the square
        # of the module would take sixteen.
        assert cpu(large) < 7 * max(cpu(small), 1e-3)
