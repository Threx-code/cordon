"""The rules for names an MCP server borrows (`lookalike_names`), declared beside the agent catalogue's own."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import Category, Confidence, Severity


class LookalikeRules:
    """`SUSPECT.MCP.LOOKALIKE.002` and `SUSPECT.MCP.TOOL_NAME_LOOKALIKE.001`."""

    @staticmethod
    def build_rules(rule: Callable[..., Any]) -> dict[str, Any]:
        return {
            "SUSPECT.MCP.LOOKALIKE.002": rule(
                "SUSPECT.MCP.LOOKALIKE.002",
                "This MCP server's own package is named like a popular one",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "This MCP server's manifest names its own package one or two characters from a "
                "widely used server's or SDK's, or under a scope one character from its scope: the "
                "name a person types or an agent's installer resolves when it meant the real one.",
                "Install the real package by its exact name, and do not install this one.",
                (ref.MCP_SECURITY,),
            ),
            "SUSPECT.MCP.TOOL_NAME_LOOKALIKE.001": rule(
                "SUSPECT.MCP.TOOL_NAME_LOOKALIKE.001",
                "An MCP tool is named one letter from a well-known tool",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "This MCP server registers a tool whose name is one edit from a well-known tool's "
                "(a reference server's `read_file`, `git_status`, `create_issue`). An agent choosing "
                "a tool by name can call this one in place of the real one (tool shadowing).",
                "Name the tool for what it does, and check why it imitates another tool's name.",
                (ref.MCP_SECURITY,),
            ),
        }
