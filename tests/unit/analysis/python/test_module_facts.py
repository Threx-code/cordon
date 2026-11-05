"""Item 32, pass 1: the Python analyser's name tables built one top-level statement at a time, each
statement parsed alone, are the tables built from the whole module's tree (design note 32). Every
later reader resolves names through these tables, so this identity is what keeps every finding the
same once no tree of the whole module exists."""

from __future__ import annotations

import ast
import gc
import itertools
import sys
import textwrap
import time
import tracemalloc
from collections.abc import Callable
from typing import ClassVar

import pytest

from cordon_scanner.analysis.python.module_facts import ModuleFacts, StatementTrees
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.statements import PythonStatements, StatementScan

DECODE = "b64" + "decode"

CASES = {
    "imports": """
        import base64 as b
        import os, subprocess as sp
        from urllib.request import urlopen as fetch
        from . import sibling
        """,
    "an alias inside a function, used at the top after it": """
        def helper():
            import os as o
            return o
        run = o.system
        """,
    "an alias at the top, used inside a function before it": """
        def later():
            return go("x")
        import subprocess
        go = subprocess.run
        """,
    "bindings and tuples": """
        import os
        f = os.system
        a, b = eval, exec
        c = d = os.popen
        """,
    "strings bound once, twice the same, twice different": """
        ONE = "base64"
        SAME = "x"
        SAME = "x"
        OTHER = "a"
        OTHER = "b"
        """,
    "sketches": """
        URL = f"https://{HOST}/x"
        BUILT = "a" + "b"
        TWICE = f"{a}"
        TWICE = f"{b}"
        """,
    "plain literals and a reassignment": """
        NAME = "eval"
        NAME = "exec"
        MIXED = "x"
        MIXED = compute()
        """,
    "bundled paths and local reads": """
        import os
        HERE = os.path.dirname(__file__)
        text = open("README.md").read()
        for line in open("setup.cfg"):
            pass
        body = Path("x.txt").read_text()
        """,
    "an enumerated loop": """
        for mod in ["fastapi", "uvicorn"]:
            try:
                __import__(mod)
            except ImportError:
                pass
        """,
    "probes": f"""
        try:
            __import__(name)
        except (ImportError, ValueError):
            pass
        import base64
        base64.{DECODE}
        """,
    "a probe vetoed by a later statement": """
        try:
            __import__(name)
        except ModuleNotFoundError:
            pass
        mod = sys.modules[name]
        """,
    "decorated and compound statements": """
        @decorator
        def first():
            import json as j
        if True:
            import os as oo
        else:
            import sys as oo
        try:
            x = j.loads
        finally:
            y = oo.getcwd
        class K:
            import shutil as sh
        z = sh.rmtree
        """,
    "two statements on a line": """
        import os as p; q = p.system
        """,
}


class ModuleFactsKit:
    @staticmethod
    def whole(text: str) -> ModuleFacts:
        """Today's tables: the whole module parsed once, the names collected from its tree."""
        analyzer = PythonAnalyzer()
        analyzer._collect_names(PythonSyntax.shared(text))
        return ModuleFacts.of(analyzer)

    @staticmethod
    def same(left: ModuleFacts, right: ModuleFacts) -> None:
        assert left.aliases == right.aliases
        assert left.bindings == right.bindings
        assert left.strings == right.strings
        assert {k: ast.dump(v) for k, v in left.sketches.items()} == {
            k: ast.dump(v) for k, v in right.sketches.items()
        }
        assert left.plain_literals == right.plain_literals
        assert left.bundled_paths == right.bundled_paths
        assert left.local_reads == right.local_reads
        assert left.enumerated == right.enumerated
        assert left.probes == right.probes


class TestOneStatementAtATime:
    @pytest.mark.parametrize("name", sorted(CASES))
    def test_the_tables_are_the_whole_tree_s(self, name: str) -> None:
        text = textwrap.dedent(CASES[name])
        ModuleFactsKit.same(ModuleFacts.build(text), ModuleFactsKit.whole(text))

    def test_every_table_is_exercised(self) -> None:
        """A guard on the cases themselves: an identity of empty tables would prove nothing."""
        built = [ModuleFacts.build(textwrap.dedent(t)) for t in CASES.values()]
        for table in (
            "aliases", "bindings", "strings", "sketches", "plain_literals", "bundled_paths",
            "local_reads", "enumerated", "probes",
        ):  # fmt: skip
            assert any(getattr(facts, table) for facts in built), table

    def test_a_probe_is_named_by_its_place_not_its_node(self) -> None:
        """No node outlives its statement, so a probe is its span: stable across parses."""
        text = textwrap.dedent(CASES["probes"])
        assert ModuleFacts.build(text).probes == frozenset({(3, 4, 3, 20)})

    def test_the_veto_reaches_back_across_statements(self) -> None:
        text = textwrap.dedent(CASES["a probe vetoed by a later statement"])
        assert ModuleFacts.build(text).probes == frozenset()

    def test_lines_are_the_file_s(self) -> None:
        """Each statement is parsed alone at the line it starts on in the file."""
        text = "import os\n\n\nx = 1\n" + textwrap.dedent(CASES["probes"])
        assert ModuleFacts.build(text).probes == frozenset({(7, 4, 7, 20)})


#: Snippets whose statement starts depend on reading strings, comments and brackets right.
SCANNED = {
    "strings that look like code": 'x = "# not a comment"\ny = \'a\\\'b\'\nz = r"\\\\"\nq = "(["\n',
    "a triple-quoted string with column-0 lines": 'D = """\nimport os\ndef f():\n"""\nn = 1\n',
    "brackets across lines": "v = [\n1,\n2]\nw = {\n'a': (1,\n2)}\n",
    "a backslash continuation": "a = 1 + \\\n2\nb = 3\n",
    "f-strings with nested fields and quotes": 's = f"{x!r:>{width}} {d[\'k\']}"\nt = f"{{literal}}"\nu = f\'{"q"}\'\nv = 1\n',
    "a nested same-quote f-string (3.12)": 's = f"{d["k"]}"\nt = 2\n',
    "compound statements and decorators": "@a\n@b(1)\ndef f():\n    pass\nif x:\n    y\nelif z:\n    w\nelse:\n    v\ntry:\n    p\nexcept E:\n    q\nfinally:\n    r\nk = 1\n",
    "a match statement": "match x:\n    case 1:\n        pass\nm = 1\n",
    "comments and blank lines between": "# head\n\nx = 1\n\n# between\n\ny = 2  # trailing\n",
    "bytes and prefixes": "a = b'x'\nb = rb'\\d'\nc = Rb\"x\"\nd = u'x'\ne = br'y'\n",
}


#: Cases written in syntax only a newer Python parses (PEP 701's f-strings are 3.12's): not a module
#: on an older one, so not a case there.
SCANNED = {
    name: text
    for name, text in SCANNED.items()
    if "(3.12)" not in name or sys.version_info >= (3, 12)
}


class TestTheScan:
    @pytest.mark.parametrize("name", sorted(SCANNED))
    def test_its_starts_are_the_tokenizer_s(self, name: str) -> None:
        text = SCANNED[name]
        ast.parse(text)  # a guard on the fixture: only a module that parses has true starts
        assert StatementScan.starts(text) == PythonStatements.starts(text)

    def test_every_case_s_pieces_parse(self) -> None:
        for text in (*SCANNED.values(), *(textwrap.dedent(t) for t in CASES.values())):
            starts = [*StatementScan.starts(text), len(text)]
            for at, end in itertools.pairwise(starts):
                ast.parse(text[at:end])

    def test_a_string_left_open_is_one_piece(self) -> None:
        assert StatementScan.starts("x = 'never closed\ny = 1\n") == [0]


class TestTheRoute:
    def test_a_statement_over_half_the_module_parses_the_whole(self) -> None:
        text = "import os\nDATA = '" + "A" * 10_000 + "'\nx = os.system\n"
        assert StatementTrees.pieces(text) is None
        ModuleFactsKit.same(ModuleFacts.build(text), ModuleFactsKit.whole(text))

    def test_a_piece_that_does_not_parse_falls_back_to_the_whole(self, monkeypatch) -> None:
        """A wrong cut (here forced: inside a bracket) leaves a piece that cannot parse; the tables
        are the whole module's all the same."""
        text = "import os as o\nv = [\n1]\nw = o.system\n" + "z = 1\n" * 10
        cut = text.index("1]")
        monkeypatch.setattr(StatementScan, "starts", staticmethod(lambda _: [0, cut]))
        ModuleFactsKit.same(ModuleFacts.build(text), ModuleFactsKit.whole(text))

    def test_a_module_that_does_not_parse_raises_as_the_whole_does(self) -> None:
        with pytest.raises(SyntaxError):
            ModuleFacts.build("x = 1\n" * 10 + "def (:\n")


class TestCost:
    def test_lines_are_counted_once_not_once_per_statement(self) -> None:
        """Each statement's line was counted from the module's start: over k statements about n·k/2
        characters (outer-layer review). Four times the statements must cost about four times the
        CPU, not sixteen (process time as a ratio, never wall time)."""
        small = "".join(f"v{i} = {i}\n" for i in range(10_000))
        large = "".join(f"v{i} = {i}\n" for i in range(40_000))
        spans_small, spans_large = StatementTrees.pieces(small), StatementTrees.pieces(large)
        assert spans_small is not None and spans_large is not None

        def cpu(text: str, spans: list[tuple[int, int]]) -> float:
            best = float("inf")
            for _ in range(3):
                started = time.process_time()
                for _tree, index in StatementTrees.each(text, spans):
                    StatementTrees.release(index)
                best = min(best, time.process_time() - started)
            return best

        assert cpu(large, spans_large) < 6 * max(cpu(small, spans_small), 0.002)

    def test_lines_stay_the_file_s(self) -> None:
        text = "x = 1\n\n\ny = 2\nz = [\n3]\nw = 4\n"
        spans = StatementTrees.pieces(text)
        assert spans is not None
        lines = []
        for tree, index in StatementTrees.each(text, spans):
            lines.append(tree.body[0].lineno)
            StatementTrees.release(index)
        assert lines == [1, 4, 5, 7]


class TestPeak:
    """Item 32's rule: no shape costs more than today's whole-module collection (tracemalloc)."""

    SHAPES: ClassVar[dict[str, Callable[[], str]]] = {
        "one-line literal": lambda: "import base64\nDATA = '" + "QUJD" * 300_000 + "'\nx = 1\n",
        "multi-line literal": lambda: (
            'import os\nDATA = """' + ("QUJD" * 19 + "\n") * 16_000 + '"""\nx = 1\n'
        ),
        "two literals": lambda: (
            "".join(f"D{i} = '" + "QUJD" * 150_000 + "'\n" for i in range(2)) + "x = 1\n"
        ),
        "tree-heavy": lambda: "".join(
            f"v{i} = f(a{i}, b={i}, c=[{i}, {i} + 1])\n" for i in range(12_000)
        ),
    }

    BOOKKEEPING = 4096

    @staticmethod
    def peak(run: Callable[[], object]) -> int:
        gc.collect()
        tracemalloc.start()
        try:
            run()
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
            PythonSyntax.shared.cache_clear()

    @pytest.mark.parametrize("shape", sorted(SHAPES))
    def test_no_shape_costs_more_than_the_whole_module(self, shape: str) -> None:
        text = self.SHAPES[shape]()
        # Both run once first, so neither is charged a first call's one-off allocations.
        ModuleFacts.build(text), ModuleFactsKit.whole(text), PythonSyntax.shared.cache_clear()
        # A fixed allowance for the route's own bookkeeping, not a multiple of the file: where a
        # statement is over half the module the route is the whole module's parse, plus 400 bytes
        # measured (1 Nov), on a peak of megabytes.
        assert (
            self.peak(lambda: ModuleFacts.build(text))
            <= self.peak(lambda: ModuleFactsKit.whole(text)) + self.BOOKKEEPING
        )
