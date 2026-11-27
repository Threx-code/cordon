"""The package-intel refresh asks registries as any browser would: no header names Cordon or its repository."""

from __future__ import annotations

import ast

from support import ROOT

SCRIPT = ROOT / "scripts" / "refresh" / "refresh_package_intel.py"
NAMING = ("cordon", "threx")


class Strings:
    """Every string constant in the script, and the value the agent constant holds."""

    @staticmethod
    def tree() -> ast.Module:
        return ast.parse(SCRIPT.read_text(encoding="utf-8"))

    @classmethod
    def agent(cls) -> str:
        for node in cls.tree().body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "USER_AGENT" for t in node.targets
            ):
                return str(ast.literal_eval(node.value))
        raise AssertionError("the script defines no USER_AGENT")

    @classmethod
    def header_values(cls) -> list[ast.expr]:
        """The expression sent as `User-Agent` wherever the script builds a header dict."""
        found: list[ast.expr] = []
        for node in ast.walk(cls.tree()):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value == "User-Agent":
                        found.append(value)
        return found


class TestGenericAgent:
    def test_the_agent_names_neither_cordon_nor_the_repository(self) -> None:
        agent = Strings.agent().lower()
        assert agent
        assert not any(word in agent for word in NAMING)

    def test_every_request_sends_that_agent_and_nothing_else(self) -> None:
        values = Strings.header_values()
        assert values, "the script builds no request header"
        for value in values:
            assert isinstance(value, ast.Name)
            assert value.id == "USER_AGENT"

    def test_no_header_literal_in_the_script_names_cordon(self) -> None:
        """A header written inline, beside the constant, is still a header."""
        for value in Strings.header_values():
            if isinstance(value, ast.Constant):
                assert not any(word in str(value.value).lower() for word in NAMING)
