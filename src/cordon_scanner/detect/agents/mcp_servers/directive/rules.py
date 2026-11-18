"""The rules for the table of orders and tricks in the text an MCP server hands the agent
(`directive_table.py`): one rule for each class on each surface, built from the table so that a new
row is a new rule with the wording of its row. The catalogue merges them in."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.agents.mcp_servers.directive.table import DirectiveTable
from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import Category, Confidence, Severity


class DirectiveRules:
    @staticmethod
    def build_rules(rule: Callable[..., Any]) -> dict[str, Any]:
        """One rule per (class, surface) of the table, built with the catalogue's rule factory."""
        out: dict[str, Any] = {}
        for directive in DirectiveTable.classes():
            for surface in directive.surfaces:
                where = DirectiveTable.surface_name(surface)
                rule_id = DirectiveTable.rule_id(surface, directive.id)
                out[rule_id] = rule(
                    rule_id,
                    f"{where[0].upper()}{where[1:]} of an MCP server {directive.does}",
                    Category.SUSPICIOUS,
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    f"Text in {where} of this MCP server {directive.does}. {directive.why}",
                    "Read the text in full. Do not use the server until it is explained.",
                    (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
                )
        return out


__all__ = ["DirectiveRules"]
