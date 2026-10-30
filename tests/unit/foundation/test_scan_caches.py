"""The caches that hold a scan's files are empty once the scan returns, and an identity-keyed store
never answers a second object with the first one's entry."""

from __future__ import annotations

import gc
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pysyntax import TreeIndex
from cordon_scanner.analysis.shared.segmented_parse import WholeFileCalls
from cordon_scanner.engine.engine import Engine
from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.text.literals import LiteralGate


class CacheKit:
    @staticmethod
    def project(root: Path) -> Path:
        root.mkdir()
        (root / "setup.py").write_text(
            '"""A package."""\nimport os\n\ndef run(value):\n    return os.getenv(value)\n' * 40,
            encoding="utf-8",
        )
        (root / "index.js").write_text(
            "/* a block comment\n * spanning lines */\nconst cp = require('child_process');\n" * 40,
            encoding="utf-8",
        )
        (root / "package.json").write_text('{"name": "p", "version": "1.0.0"}', encoding="utf-8")
        return root

    @staticmethod
    def held() -> dict[str, int]:
        """Each registered cache's size, by what it is."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax
        from cordon_scanner.analysis.shared.documentation import DocumentationSpans
        from cordon_scanner.detect.base import RuleSelector
        from cordon_scanner.detect.infra.config_files import ConfigDetector
        from cordon_scanner.foundation.text.comments import SourceComments

        return {
            "rule globs": RuleSelector._pattern_matches.cache_info().currsize,
            "config globs": ConfigDetector._pattern_matches.cache_info().currsize,
            "comment spans": SourceComments.block_comment_spans.cache_info().currsize,
            "documentation": DocumentationSpans.of.cache_info().currsize,
            "python trees": PythonSyntax.shared.cache_info().currsize,
            "tree indexes": len(TreeIndex.RECENT),
            "literal gates": len(LiteralGate._recent),
            "whole-file calls": len(WholeFileCalls._cache),
        }


class TestEmptiedAfterEveryScan:
    def test_a_scan_leaves_every_registered_cache_empty(self, tmp_path: Path) -> None:
        config = Config.default().with_overrides(use_cache=False)
        engine = Engine(config)
        held_during: dict[str, int] = {}
        scan = engine._scan

        def watched(target: Any) -> Any:
            result = scan(target)
            held_during.update(CacheKit.held())
            return result

        engine._scan = watched  # type: ignore[method-assign]
        engine.scan(CacheKit.project(tmp_path / "p"))
        assert sum(held_during.values()) > 0, (
            f"nothing was cached, so this proves nothing: {held_during}"
        )
        assert not any(CacheKit.held().values()), CacheKit.held()

    def test_they_are_emptied_when_the_scan_raises(self, tmp_path: Path) -> None:
        LiteralGate((b"needle",)).present(b"a haystack with a needle")
        assert LiteralGate._recent
        engine = Engine(Config.default().with_overrides(use_cache=False))

        def fails(target: Any) -> Any:
            raise RuntimeError("the scan failed")

        engine._scan = fails  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            engine.scan(tmp_path)
        assert not LiteralGate._recent

    def test_the_registry_empties_both_kinds(self) -> None:
        import functools

        calls: list[str] = []

        @functools.lru_cache(maxsize=4)
        def memo(text: str) -> str:
            calls.append(text)
            return text.upper()

        store: dict[int, object] = {1: object()}
        ScanCaches.register(memo)
        ScanCaches.register(store)
        memo("x")
        ScanCaches.after_scan()
        memo("x")
        assert calls == ["x", "x"] and not store


class TestAnIdentityIsNeverMistaken:
    """Each identity-keyed store, handed a second object under the first one's identity (the reuse a
    freed object's id allows), answers for the second object: its entry keeps the object and checks it
    with `is`. Deterministic: the identity is patched, not left to the allocator."""

    def test_the_literal_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ScanCaches.after_scan()
        gate = LiteralGate((b"needle",))
        assert gate.present(b"this one holds the needle")
        monkeypatch.setattr(ScanCaches, "identity", staticmethod(lambda obj: 7))
        first = b"this one holds the needle, again"
        assert gate.present(first)
        assert not gate.present(b"and this one holds nothing of the kind")

    def test_the_whole_file_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ScanCaches.after_scan()
        monkeypatch.setattr(ScanCaches, "identity", staticmethod(lambda obj: 7))

        class Source:
            def __init__(self, data: bytes) -> None:
                self.data, self.size = data, len(data)

            def reader(self) -> Any:
                import contextlib

                @contextlib.contextmanager
                def opened() -> Any:
                    yield lambda start, length: self.data[start : start + length]

                return opened()

        computed: list[int] = []

        class Provider:
            def resolve_parts(self, parts: Any) -> list[tuple[int, Any]]:
                list(parts)
                computed.append(1)
                return []

        first, second = Source(b"first();\n"), Source(b"second();\nsecond();\n")
        WholeFileCalls._located(Provider(), first)
        WholeFileCalls._located(Provider(), second)  # the first one's identity, another object
        assert len(computed) == 2, "the second source was answered from the first one's entry"
        WholeFileCalls._located(Provider(), second)  # the same object again: kept
        assert len(computed) == 2, "an object the store holds was worked out again"


class TestNoAnalysisOutlivesItsFile:
    def test_no_python_analyser_survives_a_scan(self, tmp_path: Path) -> None:
        from cordon_scanner.analysis.python.py_flow import PythonValueFlow
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        Scanner(Config.default().with_overrides(use_cache=False)).scan(
            CacheKit.project(tmp_path / "p")
        )
        gc.collect()
        alive = [o for o in gc.get_objects() if isinstance(o, (PythonAnalyzer, PythonValueFlow))]
        assert not alive, f"{len(alive)} analysers, and their id()-keyed maps, outlived the scan"

    def test_an_indexed_tree_is_freed_by_reference_counts_alone(self) -> None:
        """A list of a subtree's nodes starts with the subtree's root, so one kept on the root made
        the tree reference itself, and every tree waited for the cycle collector (D1). Kept on the
        index, the tree goes the moment its index does, with the collector off."""
        import ast
        import weakref

        from cordon_scanner.analysis.python.execution_flows import ExecutionFlows
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        source = "class A:\n    def f(self):\n        return 1\n\ndef g():\n    pass\n" * 50
        ScanCaches.after_scan()
        tree = PythonSyntax.shared(source)
        function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        # Every per-subtree list, including ones that hold the node they are kept for.
        PythonSyntax.of(tree, ast.Module, ast.FunctionDef)
        PythonSyntax.of(function, ast.FunctionDef)
        PythonSyntax.nodes(function)
        ExecutionFlows._scope_walk(function)
        ExecutionFlows._scope_walk(tree)
        PythonSyntax.parents(function)
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        PythonAnalyzer._prepared(tree)
        dead = weakref.ref(tree)
        del tree, function
        gc.disable()
        try:
            ScanCaches.after_scan()  # the shared-tree and index caches let it go
            assert dead() is None, "the tree outlived its caches: something in it refers to it"
        finally:
            gc.enable()
