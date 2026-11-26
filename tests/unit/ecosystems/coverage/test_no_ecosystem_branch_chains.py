"""No feature branches on ecosystem names. A function that tests a value against two or more ecosystem names
(`if ecosystem == "npm": … elif ecosystem == "pypi": …`) is a feature that has to be edited for every ecosystem added,
and is how a feature ends up covering a few: each ecosystem's behaviour belongs to its own adapter
(`EcosystemRegistry`) or to one table, so a new ecosystem is a new adapter or a row, never an edit here.

Outside an ecosystem's own adapter (`ecosystems/`), a single name counts too: `if ecosystem == "npm": check()` is a
feature built for one ecosystem. The sites found on 2026-11-26 are listed in `ecosystem_chains.json`. A new one fails; a listed one that is gone must
be taken off, so the list only shrinks. Each is replaced by adapter or table dispatch when its feature is built."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import ClassVar

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from support import ROOT


class Chains:
    SOURCE: ClassVar[Path] = ROOT / "src" / "cordon_scanner"
    RECORD: ClassVar[Path] = (
        ROOT / "tests" / "unit" / "ecosystems" / "coverage" / "ecosystem_chains.json"
    )
    IDS: ClassVar[frozenset[str]] = frozenset(EcosystemRegistry.BY_ID) | {"vscode", "openvsx"}

    @classmethod
    def named(cls, node: ast.AST) -> set[str]:
        """The ecosystem names a branch tests against, whatever the tested value is called: a comparison
        (`kind == "npm"`, `eco in ("pypi", "cargo")`), a `case "npm":` pattern, or a prefix test
        (`purl.startswith("pkg:npm")`)."""
        found: set[str] = set()
        if isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                for leaf in ast.walk(side):
                    if (
                        isinstance(leaf, ast.Constant)
                        and isinstance(leaf.value, str)
                        and leaf.value in cls.IDS
                    ):
                        found.add(leaf.value)
        elif isinstance(node, ast.match_case):
            for leaf in ast.walk(node.pattern):
                if (
                    isinstance(leaf, ast.Constant)
                    and isinstance(leaf.value, str)
                    and leaf.value in cls.IDS
                ):
                    found.add(leaf.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("startswith", "endswith")
        ):
            for leaf in ast.walk(node):
                if isinstance(leaf, ast.Constant) and isinstance(leaf.value, str):
                    tail = leaf.value.removeprefix("pkg:").rstrip("/:@")
                    if tail in cls.IDS:
                        found.add(tail)
        return found

    @classmethod
    def found(cls) -> dict[str, list[str]]:
        """`file::function` -> the ecosystem names it branches on, for every function naming two or more."""
        sites: dict[str, list[str]] = {}
        for path in sorted(cls.SOURCE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names: set[str] = set()
                    for inner in ast.walk(node):
                        names |= cls.named(inner)
                    # Outside an ecosystem's own adapter (`ecosystems/`), even one name is a feature built for that one:
                    # `if ecosystem == "npm": check()` is how a feature ends up covering a few.
                    inside_adapter = path.relative_to(cls.SOURCE).parts[0] == "ecosystems"
                    if len(names) >= (2 if inside_adapter else 1):
                        key = f"{path.relative_to(ROOT).as_posix()}::{node.name}"
                        sites[key] = sorted(set(sites.get(key, [])) | names)
        return sites

    @classmethod
    def recorded(cls) -> dict[str, list[str]]:
        loaded = json.loads(cls.RECORD.read_text(encoding="utf-8"))
        return {str(k): list(v) for k, v in loaded.items()}


class TestNoEcosystemBranchChains:
    def test_no_new_chain(self) -> None:
        new = sorted(set(Chains.found()) - set(Chains.recorded()))
        assert not new, (
            "a function branches on ecosystem names: give each ecosystem's behaviour to its adapter or a table, "
            f"so a new ecosystem is a new adapter or row: {new}"
        )

    def test_a_listed_chain_that_is_gone_is_taken_off(self) -> None:
        gone = sorted(set(Chains.recorded()) - set(Chains.found()))
        assert not gone, f"remove from ecosystem_chains.json (the chain is gone): {gone}"

    def test_the_scan_finds_a_chain_and_not_a_single_check(self) -> None:
        def names(source: str) -> set[str]:
            return set().union(*(Chains.named(n) for n in ast.walk(ast.parse(source))))

        assert names(
            'def f(kind):\n    if kind == "npm":\n        a()\n    elif kind in ("pypi", "cargo"):\n        b()\n'
        ) == {
            "npm",
            "pypi",
            "cargo",
        }
        assert names(
            'def f(x):\n    match x:\n        case "npm":\n            a()\n        case "pypi":\n            b()\n'
        ) == {
            "npm",
            "pypi",
        }
        assert names(
            'def f(p):\n    return p.startswith("pkg:npm/") or p.startswith("pkg:cargo/")\n'
        ) == {"npm", "cargo"}
        assert names('def g(e):\n    return e == "npm"\n') == {"npm"}
