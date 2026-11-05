"""The parser's grammar classes: what each area of the language declares it calls in the others."""

from __future__ import annotations

import ast
import inspect

from cordon_scanner.analysis.javascript.front.grammar import stream
from cordon_scanner.analysis.javascript.front.grammar.stream import TokenStream
from cordon_scanner.analysis.javascript.front.parser import Parser


class Grammar:
    @staticmethod
    def declared() -> list[str]:
        """The methods declared in TokenStream's TYPE_CHECKING block."""
        tree = ast.parse(inspect.getsource(stream))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TokenStream")
        return [
            m.name
            for block in cls.body
            if isinstance(block, ast.If) and ast.unparse(block.test) == "TYPE_CHECKING"
            for m in block.body
            if isinstance(m, ast.FunctionDef)
        ]

    @staticmethod
    def parts() -> list[type]:
        """The classes Parser is assembled from, Parser itself included, the token stream not."""
        return [c for c in Parser.__mro__ if c not in (TokenStream, object)]

    @staticmethod
    def callers(name: str) -> set[type]:
        """The grammar classes whose own methods call `self.<name>`."""
        found = set()
        for part in Grammar.parts():
            tree = ast.parse(inspect.getsource(part))
            if any(
                isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)
                and n.value.id == "self"
                and n.attr == name
                for n in ast.walk(tree)
            ):
                found.add(part)
        return found


class TestDeclarations:
    def test_some_are_declared(self) -> None:
        assert Grammar.declared()

    def test_each_has_exactly_one_definition(self) -> None:
        counts = {
            name: [p.__name__ for p in Grammar.parts() if name in vars(p)]
            for name in Grammar.declared()
        }
        assert {n: where for n, where in counts.items() if len(where) != 1} == {}

    def test_none_exists_at_run_time(self) -> None:
        assert [n for n in Grammar.declared() if n in vars(TokenStream)] == []

    def test_each_is_called_across_areas(self) -> None:
        # A declaration only its own area calls says nothing a reader needs: it has outlived the
        # call that once crossed.
        owner = {n: next(p for p in Grammar.parts() if n in vars(p)) for n in Grammar.declared()}
        stale = [n for n in Grammar.declared() if not (Grammar.callers(n) - {owner[n]})]
        assert stale == []
