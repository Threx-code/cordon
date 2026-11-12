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

    def test_a_forgotten_tree_is_walked_again_the_same(self) -> None:
        tree = PythonSyntax.parse(self.SOURCE)
        before = [id(n) for n in PythonSyntax.walked(tree)]
        PythonSyntax.forget(tree)
        assert [id(n) for n in PythonSyntax.walked(tree)] == before
