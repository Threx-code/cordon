"""A Python module's name tables, built one top-level statement at a time (item 32, pass 1).

The Python analyser resolves every call through tables built from the module first: aliases, bindings,
the strings and built strings names hold, the names that read local files or bundle paths, loops over
literal lists, and `__import__` probes. Built from a tree of the whole module, they cost that tree:
about 233 bytes per source byte while it parses, held until the file is done. Built here, each
statement is parsed alone, its names collected, and its tree dropped before the next is parsed, so
the parse costs the largest statement, not the module (design note 32).

```
  text --StatementScan--> statement spans (characters only: no tokens, no tree)
     one statement over half the module?  -> parse the whole module, as today (no more than today)
     else each span: parse alone at its own line -> index (depth-first) -> collect -> drop the tree
          a span that does not parse      -> parse the whole module, as today (the cut was wrong,
                                             or the module does not parse: the same raise)
  then once: what only the whole module decides (plain literals, the probes' veto)
```

Peak, then, is never above today's: the whole module's parse where a statement dominates or a cut
fails, else a piece (at most half the text) and its parse, which is well under the whole module's
on every shape measured (tests/unit/analysis/python/test_module_facts.py::TestPeak).

The tables are the whole tree's, by construction: the same collection runs on each statement, an
indexed tree is read depth-first, and a module's depth-first order is its statements' own, one after
the other (tests/unit/analysis/python/test_module_facts.py holds the identity, table by table).
"""

from __future__ import annotations

import ast
import contextlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pysyntax import PythonSyntax, TreeIndex
from cordon_scanner.analysis.python.statements import StatementScan

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore


@dataclass(frozen=True)
class ModuleFacts:
    """The name tables the analyser resolves through, as plain data. `sketches` holds each built
    string's own expression, a subtree of its statement only (`_sketch` reads its parts)."""

    aliases: dict[str, str]
    bindings: dict[str, str]
    strings: dict[str, str | None]
    sketches: dict[str, ast.AST]
    plain_literals: frozenset[str]
    bundled_paths: frozenset[str]
    local_reads: frozenset[str]
    enumerated: frozenset[str]
    probes: frozenset[tuple[int, int, int, int]]

    @staticmethod
    def of(analyzer: AnalyzerCore) -> ModuleFacts:
        """The tables an analyser holds once its names are complete."""
        return ModuleFacts(
            aliases=dict(analyzer._aliases),
            bindings=dict(analyzer._bindings),
            strings=dict(analyzer._strings),
            sketches=dict(analyzer._sketches),
            plain_literals=frozenset(analyzer._plain_literals),
            bundled_paths=frozenset(analyzer._bundled_paths),
            local_reads=frozenset(analyzer._local_reads),
            enumerated=frozenset(analyzer._enumerated),
            probes=frozenset(analyzer._probes),
        )

    @staticmethod
    def build(text: str) -> ModuleFacts:
        """The module's tables, one statement parsed at a time, or from the whole module's tree
        where that costs no more (`StatementTrees.pieces`) or a piece does not parse. Raises what
        the whole module's parse raises (`SyntaxError`, `ValueError`, `RecursionError`)."""
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        pieces = StatementTrees.pieces(text)
        if pieces is not None:
            analyzer = PythonAnalyzer()
            try:
                for tree, index in StatementTrees.each(text, pieces):
                    analyzer._collect_statement(tree)
                    StatementTrees.release(index)
            except (SyntaxError, ValueError, RecursionError):
                pieces = (
                    None  # a cut that is not between statements, or a module that does not parse
                )
            else:
                analyzer._names_complete()
                return ModuleFacts.of(analyzer)
        whole = PythonAnalyzer()
        whole._collect_names(PythonSyntax.shared(text))
        return ModuleFacts.of(whole)


class StatementTrees:
    """Each top-level statement of a module, parsed alone at the lines it has in the file."""

    @staticmethod
    def pieces(text: str) -> list[tuple[int, int]] | None:
        """The statements' spans, or None where one statement is more than half the module: then
        that statement's parse is most of the whole module's, and its text copied out for parsing
        alone would cost more than parsing the module (a 13.6 MB setup.py that is one literal: 95
        MB, against 41 MB whole). Cut from characters (`StatementScan`), not tokens, which would
        hold a copy of the text and of each token."""
        starts = StatementScan.starts(text)
        spans = list(zip(starts, [*starts[1:], len(text)], strict=True))
        if max(end - start for start, end in spans) * 2 > len(text):
            return None
        return spans

    @staticmethod
    def each(text: str, spans: list[tuple[int, int]]) -> Iterator[tuple[ast.Module, TreeIndex]]:
        """Each statement's tree with its index, which the caller keeps alive while it reads the
        tree (the index is what makes the reading depth-first) and releases after. A piece's copy
        is freed before the next is made. Lines are counted as the spans advance, so the module is
        scanned for newlines once, not once per statement (outer-layer review of 41560302)."""
        counted, line = 0, 0
        for start, end in spans:
            line += text.count("\n", counted, start)
            counted = start
            piece = text[start:end]
            if not piece.strip():
                continue
            tree = PythonSyntax.parse(piece)
            del piece
            # Statements start at a line's start (`StatementScan.starts`): only the line moves.
            ast.increment_lineno(tree, line)
            yield tree, TreeIndex.build(tree)

    @staticmethod
    def release(index: TreeIndex) -> None:
        """Drop a statement's index from the recent ones, so its tree is freed with it: the recent
        indexes hold their trees, and pass 1 never asks for a statement again."""
        with contextlib.suppress(ValueError):  # already pushed out by newer ones
            TreeIndex.RECENT.remove(index)


__all__ = ["ModuleFacts", "StatementTrees"]
