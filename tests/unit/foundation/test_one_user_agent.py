"""The product names itself in one place: every request in `src/` takes its agent from `version.USER_AGENT`.

The agent is the product's name and version. It never carries a repository address or an email: a header is read by
whoever keeps a registry's logs, and the product runs on customers' machines.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cordon_scanner.version import USER_AGENT, __version__
from support import ROOT

SOURCES = sorted((ROOT / "src").rglob("*.py"))
HEADER = "user-agent"
HOME = "cordon_scanner.version"
VERSION_FILE = ROOT / "src" / "cordon_scanner" / "version.py"
OWN_NAMES = frozenset({"USER_AGENT", "_UA"})


class Sites:
    """Every place a module sets an agent: a header dict entry, `add_header`, or a constant with AGENT in its name."""

    @staticmethod
    def tree(path: Path) -> ast.Module:
        return ast.parse(path.read_text(encoding="utf-8"))

    @classmethod
    def headers(cls, path: Path) -> list[ast.expr]:
        found: list[ast.expr] = []
        for node in ast.walk(cls.tree(path)):
            if isinstance(node, ast.Dict):
                found += [
                    value
                    for key, value in zip(node.keys, node.values, strict=True)
                    if isinstance(key, ast.Constant) and str(key.value).lower() == HEADER
                ]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"add_header", "putheader"}
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).lower() == HEADER
            ):
                found.append(node.args[1])
        return found

    @classmethod
    def defined(cls, path: Path) -> list[str]:
        """Names that hold an agent of their own: USER_AGENT or _UA at any depth, AGENT at module level.

        `AGENT` inside a class is an enum member or a prompt (the AI agent), not a header.
        """
        tree = cls.tree(path)
        top = {id(n) for n in tree.body}
        names: list[str] = []
        for node in ast.walk(tree):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            names += [
                t.id
                for t in targets
                if isinstance(t, ast.Name)
                and (t.id in OWN_NAMES or (t.id == "AGENT" and id(node) in top))
            ]
        return names

    @classmethod
    def imported_from(cls, path: Path) -> list[str]:
        """The modules `USER_AGENT` is imported from, in this file."""
        found: list[str] = []
        for node in ast.walk(cls.tree(path)):
            if isinstance(node, ast.ImportFrom) and any(a.name == "USER_AGENT" for a in node.names):
                found.append(node.module or "")
        return found

    @staticmethod
    def is_the_constant(value: ast.expr) -> bool:
        """Only the bare name: `x.USER_AGENT` would be a second home, even if it points at the first."""
        return isinstance(value, ast.Name) and value.id == "USER_AGENT"


def label(path: Path) -> str:
    return str(path.relative_to(ROOT))


class TestTheAgent:
    def test_it_is_the_product_name_and_version(self) -> None:
        assert f"cordon-scanner/{__version__}" == USER_AGENT

    def test_it_names_no_repository_address_and_no_email(self) -> None:
        assert not any(mark in USER_AGENT for mark in ("http", "github", "@", "(", " "))


class TestEveryRequestTakesIt:
    def test_the_sources_are_found(self) -> None:
        assert any(p.name == "registry_request.py" for p in SOURCES)

    @pytest.mark.parametrize("path", SOURCES, ids=label)
    def test_every_agent_header_is_the_constant(self, path: Path) -> None:
        for value in Sites.headers(path):
            assert Sites.is_the_constant(value), (
                f"{label(path)}:{value.lineno}: {ast.unparse(value)}"
            )

    @pytest.mark.parametrize("path", SOURCES, ids=label)
    def test_no_module_keeps_an_agent_of_its_own(self, path: Path) -> None:
        if path == VERSION_FILE:
            pytest.skip("the home")
        assert Sites.defined(path) == [], label(path)

    @pytest.mark.parametrize("path", SOURCES, ids=label)
    def test_the_constant_is_imported_from_its_home(self, path: Path) -> None:
        assert set(Sites.imported_from(path)) <= {HOME}, label(path)
