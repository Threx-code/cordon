"""The rules for text an MCP server's handlers serve to the agent (`served_text.py`): a tool's result, a
resource's content and a prompt template. Kept beside their reader; the catalogue merges them in."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import Category, Confidence, Severity


class ServedRules:
    @staticmethod
    def build_rules(rule: Callable[..., Any]) -> dict[str, Any]:
        """The served-text rules, built with the catalogue's rule factory."""
        return {
            "SUSPECT.MCP.RESULT_INJECTION.001": rule(
                "SUSPECT.MCP.RESULT_INJECTION.001",
                "An MCP tool returns text that gives the agent orders",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool of this MCP server returns text written to the agent rather than to the "
                "user: an order to call another tool, to send something to an address, to run a "
                "command, or to keep something from the user. The text is assembled where a "
                "plain reading of the handler does not show it -- from a constant, a joined "
                "list, a template, a decoded string or a helper. The agent reads a result as "
                "its own context and acts on what it says, so a result that carries orders "
                "steers it without anything appearing to the user.",
                "Read what the tool returns. A result is data for the agent, never instructions "
                "to it. Do not use the server until this is explained.",
                (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
            ),
            "SUSPECT.MCP.RESOURCE_INJECTION.001": rule(
                "SUSPECT.MCP.RESOURCE_INJECTION.001",
                "An MCP resource serves text that gives the agent orders",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A resource of this MCP server serves text written to the agent rather than "
                "content for the user: an order to call a tool, to send something to an address, "
                "to run a command, or to keep something from the user. The agent reads a "
                "resource as trusted context, so an order written into one is followed as if "
                "the user had given it.",
                "Read what the resource serves. A resource is content, never instructions to "
                "the agent. Do not attach it to a session until this is explained.",
                (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
            ),
            "SUSPECT.MCP.PROMPT_INJECTION.001": rule(
                "SUSPECT.MCP.PROMPT_INJECTION.001",
                "An MCP prompt template carries a hidden or hostile order",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A prompt this MCP server offers contains an instruction the person choosing "
                "it would not expect: to send data to an outside address, to run a shell "
                "command, to read credential files, to drop the agent's own instructions, or "
                "text wrapped in a tag addressed to the model. A prompt template is expected to "
                "instruct the agent about the task it names, not about anything else.",
                "Read the prompt text in full before offering it to a user. Do not use the "
                "server until it is explained.",
                (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
            ),
        }


__all__ = ["ServedRules"]
