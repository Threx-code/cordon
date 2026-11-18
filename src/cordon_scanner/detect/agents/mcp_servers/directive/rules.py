"""The rules for the table of orders and tricks in the text an MCP server hands the agent and in an
agent's instruction files (`table.py`): one rule for each class on each surface, built from the table so
that a new row is a new rule with the wording of its row. The catalogue merges them in."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.agents.mcp_servers.directive.table import FILE_SURFACE, DirectiveTable
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
                if surface == FILE_SURFACE:
                    title = f"{where[0].upper()}{where[1:]} {directive.does}"
                    message = f"This {where[3:]} {directive.does}. {directive.why}"
                    remediation = "Remove the instruction. Do not use the agent with this file until it is explained."
                else:
                    title = f"{where[0].upper()}{where[1:]} of an MCP server {directive.does}"
                    message = (
                        f"Text in {where} of this MCP server {directive.does}. {directive.why}"
                    )
                    remediation = (
                        "Read the text in full. Do not use the server until it is explained."
                    )
                out[rule_id] = rule(
                    rule_id,
                    title,
                    Category.SUSPICIOUS,
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    message,
                    remediation,
                    (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
                )
        return out


__all__ = ["DirectiveRules"]
