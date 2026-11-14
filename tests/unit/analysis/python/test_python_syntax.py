"""Scanned Python is parsed without printing the warnings it raises.

Found scanning real repositories: stable-diffusion's invalid escapes (`"\\h"`) made `ast.parse`
write seven `SyntaxWarning`s to the scanner's stderr, which reads as the scanner failing in a CI
log. The source below raises two such warnings under a bare `ast.parse`.
"""

from __future__ import annotations

import warnings

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.config.settings import Config


class TestScannedPythonRaisesNoWarning:
    SOURCE = 'WINDOWS = "C:\\home\\x41"\nODD = "\\h"\n'

    def test_an_invalid_escape_in_scanned_code_is_not_printed(self, tmp_path) -> None:
        (tmp_path / "paths.py").write_text(self.SOURCE, encoding="utf-8")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            PythonSyntax.parse(self.SOURCE)
            Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert [w for w in caught if issubclass(w.category, SyntaxWarning)] == []

    def test_a_syntax_error_is_still_raised(self) -> None:
        import pytest

        with pytest.raises(SyntaxError):
            PythonSyntax.parse("def (:\n")


class TestTheWalkIsTheTreesOnce:
    """`PythonSyntax.walked`: `ast.walk`'s nodes in `ast.walk`'s order, walked once per tree, for the
    analysers that each walked all of a file (litellm 1.88.0rc2, 0.8.0)."""

    SOURCE = (
        "import os\nfrom pkg import HOOK as H\n\nclass A:\n    def f(self, x):\n"
        "        return [y for y in x if y]\n\ndef g():\n    global Z\n    os.system(H)\n"
    )

    @staticmethod
    def walk(tree) -> list:
        import ast

        return list(ast.walk(tree))

    def test_the_walk_of_a_parsed_tree_is_ast_walks(self) -> None:
        tree = PythonSyntax.parse(self.SOURCE)
        assert [id(n) for n in PythonSyntax.walked(tree)] == [id(n) for n in self.walk(tree)]

    def test_the_walk_of_an_indexed_tree_is_ast_walks_not_its_depth_first_order(self) -> None:
        import ast

        tree = PythonSyntax.shared(self.SOURCE)
        walked = [id(n) for n in PythonSyntax.walked(tree)]
        assert walked == [id(n) for n in self.walk(tree)]
        assert [id(n) for n in PythonSyntax.nodes(tree)] != walked  # `nodes` stays depth-first
        function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        assert [id(n) for n in PythonSyntax.walked(function)] == [
            id(n) for n in self.walk(function)
        ]

    def test_each_tree_is_walked_once(self, monkeypatch) -> None:
        import ast

        from cordon_scanner.foundation.collector import ScanCaches

        ScanCaches.after_scan()  # `shared` keeps a recent parse: this test's must be a new one
        for tree in (PythonSyntax.parse(self.SOURCE), PythonSyntax.shared(self.SOURCE)):
            calls: list = []
            real = ast.walk
            monkeypatch.setattr(
                ast, "walk", lambda node, calls=calls, real=real: calls.append(node) or real(node)
            )
            first = PythonSyntax.walked(tree)
            assert PythonSyntax.walked(tree) is first
            assert calls == [tree]
            monkeypatch.undo()

    def test_a_parsed_tree_it_forgets_is_freed_by_reference_counts(self) -> None:
        import gc
        import weakref

        tree = PythonSyntax.parse(self.SOURCE)
        PythonSyntax.walked(tree)
        PythonSyntax.forget(tree)
        dead = weakref.ref(tree)
        gc.disable()
        try:
            del tree
            assert dead() is None, "the walk kept on the root still refers to the tree"
        finally:
            gc.enable()

    def test_the_nodes_of_some_types_are_the_walks_in_its_order(self) -> None:
        import ast

        for tree in (PythonSyntax.parse(self.SOURCE), PythonSyntax.shared(self.SOURCE)):
            for types in (
                (ast.Call,),
                (ast.FunctionDef, ast.AsyncFunctionDef),
                (ast.Import, ast.ImportFrom, ast.Call),
                (ast.Name, ast.Attribute, ast.Constant),
                (ast.expr,),  # an abstract kind: every node that is one
                (ast.Global, ast.Nonlocal),
                (ast.While,),  # none in the file
            ):
                want = [id(n) for n in self.walk(tree) if isinstance(n, types)]
                assert [id(n) for n in PythonSyntax.walked_of(tree, *types)] == want, types
                assert PythonSyntax.walked_of(tree, *types) is PythonSyntax.walked_of(tree, *types)

    def test_a_constant_kind_matched_by_value_is_filtered_as_isinstance_does(self) -> None:
        import ast
        import warnings

        import pytest

        tree = PythonSyntax.parse(self.SOURCE + "S = 'text'\nN = 3\n")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kind = getattr(ast, "Str", None)
            if kind is None:
                pytest.skip("this Python has no ast.Str (removed in 3.14)")
            want = [id(n) for n in self.walk(tree) if isinstance(n, kind)]
            assert want  # `isinstance` by value: a Constant holding a str
            assert [id(n) for n in PythonSyntax.walked_of(tree, kind)] == want

    def test_the_trees_parents_are_the_walks_for_every_node_but_the_ctx_markers(self) -> None:
        """`BackdoorWrites` reads `PythonSyntax.parents` where it built the map from the walk: for
        every node it can start from (any but the shared `ctx` markers) the parent is the same."""
        import ast

        for tree in (PythonSyntax.parse(self.SOURCE), PythonSyntax.shared(self.SOURCE)):
            walked: dict[int, ast.AST] = {}
            for node in self.walk(tree):
                for child in ast.iter_child_nodes(node):
                    walked[id(child)] = node
            parents = PythonSyntax.parents(tree)
            for node in self.walk(tree):
                if not isinstance(node, ast.expr_context):
                    assert parents.get(id(node)) is walked.get(id(node)), type(node).__name__

    def test_the_analyser_reads_the_same_with_subtrees_answered_from_the_index(
        self, monkeypatch
    ) -> None:
        """The decoded-drop and dormant-decode readers ask order-free questions of subtrees ("is
        any name here a parameter") of `within`, the index's range lookup, where they filtered a
        kept list of each subtree's nodes: the hits are the same as with every subtree walked."""
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer
        from cordon_scanner.foundation.collector import ScanCaches

        source = (
            "import base64, subprocess\nBLOB = 'aGVsbG8='\n"
            "def drop(blob, path):\n    data = base64.b64decode(blob)\n"
            "    open(path, 'wb').write(data)\n    subprocess.run([path])\n"
            "drop(BLOB, 'x')\n"
            "def handler(task):\n    payload = task['blob']\n    raw = base64.b64decode(payload)\n"
            "    open('y', 'wb').write(raw)\n"
            "def unused():\n    k = base64.b64decode('aGk=')\n    v = k ^ 3\n"
        )

        def hits() -> list[tuple[str, int, str]]:
            ScanCaches.after_scan()
            return sorted(
                (str(h.capability), h.line, h.detail) for h in PythonAnalyzer.analyse(source)
            )

        indexed = hits()
        monkeypatch.setattr(
            PythonSyntax,
            "within",
            staticmethod(
                lambda node, *types: [n for n in PythonSyntax.nodes(node) if isinstance(n, types)]
            ),
        )
        assert hits() == indexed
        assert indexed

    def test_a_forgotten_tree_is_walked_again_the_same(self) -> None:
        tree = PythonSyntax.parse(self.SOURCE)
        before = [id(n) for n in PythonSyntax.walked(tree)]
        PythonSyntax.forget(tree)
        assert [id(n) for n in PythonSyntax.walked(tree)] == before


class TestTextOnlyLines:
    """`PythonSyntax.text_only_lines`: the lines that are only text, which a reader of a parsed file may
    not take for a read or a send (reviews/pypi-98/20 shape A, 21 shape T)."""

    SOURCE = (
        '"""Module help: ~/.aws/credentials."""\n'  # 1: docstring
        "TABLE = (\n"  # 2
        '    "cat ~/.aws/credentials "\n'  # 3: a string's own first line
        '    "continued here"\n'  # 4
        ")\n"  # 5
        "BLOCK = '''\n"  # 6
        "~/.ssh/id_rsa is named here\n"  # 7: inside a multi-line string
        "'''\n"  # 8
        "PAGE = f'''\n"  # 9
        "{home}/.aws/credentials\n"  # 10: an f-string expression starts here
        "'''\n"  # 11
    )

    def lines(self, source: str | None = None) -> frozenset[int]:
        return PythonSyntax.text_only_lines(PythonSyntax.parse(source or self.SOURCE))

    def test_a_docstring_and_the_lines_a_string_continues_on_are_text(self) -> None:
        lines = self.lines()
        assert 1 in lines
        assert 7 in lines
        assert 8 in lines

    def test_a_line_where_an_expression_starts_is_code_even_inside_an_f_string(self) -> None:
        assert 10 not in self.lines()

    def test_the_line_a_string_opens_on_is_not_claimed(self) -> None:
        lines = self.lines()
        assert 6 not in lines
        assert 3 not in lines

    def test_a_call_that_names_a_store_is_code(self) -> None:
        source = 'p = open(\n    "~/.aws/credentials"\n)\n'
        assert not self.lines(source)

    def test_the_answer_is_kept_for_a_tree(self) -> None:
        tree = PythonSyntax.parse(self.SOURCE)
        assert PythonSyntax.text_only_lines(tree) is PythonSyntax.text_only_lines(tree)


class TestStringElementLines:
    """`PythonSyntax.string_element_lines`: where a table is written one string to a line."""

    SOURCE = (
        "PATTERNS = [\n"  # 1: a list opens: code
        '    "cat ~/.aws/credentials",\n'  # 2: a string alone
        '    "cat ~/.ssh/id_rsa",\n'  # 3
        "]\n"  # 4
        'ONE = ["a", "b"]\n'  # 5: a list starts here
        "TABLE = {\n"  # 6
        '    "key": "value",\n'  # 7: strings alone
        '    "other": name,\n'  # 8: a name starts here
        "}\n"  # 9
        "def f():\n"  # 10
        "    return call(\n"  # 11
        '        "an argument",\n'  # 12
        '        flag="a keyword",\n'  # 13
        "    )\n"  # 14
        'EACH = (\n    f"{x} and",\n)\n'  # 15-17: an f-string with an expression
    )

    def lines(self) -> frozenset[int]:
        return PythonSyntax.string_element_lines(PythonSyntax.parse(self.SOURCE))

    def test_a_string_alone_on_its_line_as_an_element_or_an_argument_counts(self) -> None:
        assert {2, 3, 7, 12, 13} <= self.lines()

    def test_a_line_where_anything_else_starts_does_not(self) -> None:
        lines = self.lines()
        assert 1 not in lines
        assert 5 not in lines
        assert 8 not in lines
        assert 16 not in lines
