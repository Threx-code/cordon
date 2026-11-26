"""No feature branches on ecosystem names. A function that compares an ecosystem with two or more ecosystem names
(`if ecosystem == "npm": … elif ecosystem == "pypi": …`) is a feature that has to be edited for every ecosystem added,
and is how a feature ends up covering a few: each ecosystem's behaviour belongs to its own adapter
(`EcosystemRegistry`) or to one table, so a new ecosystem is a new adapter or a row, never an edit here.

The chains found on 2026-11-26 are listed in `ecosystem_chains.json`. A new one fails; a listed one that is gone must
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

    @staticmethod
    def subject(node: ast.AST) -> bool:
        """An expression that holds an ecosystem: a name or attribute called `ecosystem`, `eco` or `*_ecosystem`."""
        name = (
            node.id
            if isinstance(node, ast.Name)
            else node.attr
            if isinstance(node, ast.Attribute)
            else ""
        )
        return name in ("ecosystem", "eco") or name.endswith("_ecosystem")

    @classmethod
    def named(cls, node: ast.Compare) -> set[str]:
        """The ecosystem names a comparison of an ecosystem tests against."""
        sides = [node.left, *node.comparators]
        if not any(cls.subject(side) for side in sides):
            return set()
        found: set[str] = set()
        for side in sides:
            for leaf in ast.walk(side):
                if (
                    isinstance(leaf, ast.Constant)
                    and isinstance(leaf.value, str)
                    and leaf.value in cls.IDS
                ):
                    found.add(leaf.value)
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
                        if isinstance(inner, ast.Compare):
                            names |= cls.named(inner)
                    if len(names) >= 2:
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
        chain = ast.parse(
            'def f(ecosystem):\n    if ecosystem == "npm":\n        a()\n    elif ecosystem in ("pypi", "cargo"):\n        b()\n'
        )
        single = ast.parse('def g(ecosystem):\n    return ecosystem == "npm"\n')
        names = [Chains.named(n) for n in ast.walk(chain) if isinstance(n, ast.Compare)]
        assert set().union(*names) == {"npm", "pypi", "cargo"}
        assert [Chains.named(n) for n in ast.walk(single) if isinstance(n, ast.Compare)] == [
            {"npm"}
        ]
