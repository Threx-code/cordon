"""Our own research fetches ask registries as any browser would: nothing in `scripts/` names Cordon or its repository."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from support import ROOT

SCRIPTS = sorted((ROOT / "scripts").rglob("*.py"))
NAMING = ("cordon", "threx", "@")
GENERIC = "Mozilla/5.0"


class Agents:
    """The user agents a script sends: every `User-Agent` header value and every `*AGENT*` constant."""

    @staticmethod
    def tree(path: Path) -> ast.Module:
        return ast.parse(path.read_text(encoding="utf-8"))

    @classmethod
    def constants(cls, path: Path) -> dict[str, ast.expr]:
        found: dict[str, ast.expr] = {}
        for node in cls.tree(path).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and "AGENT" in target.id.upper():
                        found[target.id] = node.value
        return found

    @classmethod
    def headers(cls, path: Path) -> list[ast.expr]:
        found: list[ast.expr] = []
        for node in ast.walk(cls.tree(path)):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if isinstance(key, ast.Constant) and str(key.value).lower() == "user-agent":
                        found.append(value)
        return found

    @classmethod
    def strings(cls, path: Path) -> list[str]:
        """Every literal agent text in the file, whether in a header or in a constant."""
        values = [*cls.constants(path).values(), *cls.headers(path)]
        return [
            str(v.value) for v in values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        ]


class TestScriptsAreGeneric:
    def test_the_scripts_are_found(self) -> None:
        assert any(p.name == "refresh_package_intel.py" for p in SCRIPTS)

    @pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
    def test_no_script_names_cordon_in_an_agent(self, path: Path) -> None:
        for text in Agents.strings(path):
            assert not any(word in text.lower() for word in NAMING), f"{path.name}: {text}"

    def test_every_refresh_fetch_sends_the_generic_agent(self) -> None:
        """The refresh scripts that fetch from registries send exactly the generic agent, constant or inline."""
        for path in (ROOT / "scripts" / "refresh").glob("*.py"):
            for text in Agents.strings(path):
                assert text == GENERIC, f"{path.name}: {text}"

    def test_a_header_is_a_literal_or_the_script_constant(self) -> None:
        for path in SCRIPTS:
            constants = Agents.constants(path)
            for value in Agents.headers(path):
                assert isinstance(value, ast.Constant) or (
                    isinstance(value, ast.Name) and value.id in constants
                ), f"{path.name}: the agent is neither a literal nor one of its constants"
