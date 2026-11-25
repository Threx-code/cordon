"""The reason code a finding gives when the rule that matched it names none (rows BP-5-19, BP-5-20).

`RuleStage` gives a matched finding `R400` (malicious), `R404` (vulnerable) or `R401` (anything else). A finding of the AI-component
rules says more than that: a poisoned tool description, an attack in a skill's instructions, a capability the component should not
have, a tool list that changed since the session before. `ReasonMap.of(rule_id)` gives those their own code (`R600`, `R601`, `R602`,
`R604`), and a name that imitates another one (`R504`).

The table is by exact scanner rule id, never by prefix, so a rule added later is `R401` until someone places it, as a rule nobody has
classified is intel in `content_rule.py`. A rule that states its own `reason` is not looked up here.
"""

from __future__ import annotations

from typing import ClassVar, Final

_TOOL_POISONING: Final = (
    "SUSPECT.MCP.TOOL_POISONING.001",
    "SUSPECT.MCP.TOOL_DESCRIPTION.001",
    "SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001",
    "SUSPECT.MCP.SCHEMA_POISONING.001",
    "SUSPECT.MCP.ARGUMENT_OVERRIDE.001",
    "SUSPECT.MCP.PROMPT_INJECTION.001",
    "SUSPECT.MCP.RESOURCE_INJECTION.001",
    "SUSPECT.MCP.RESULT_INJECTION.001",
)
_SKILL_ATTACK: Final = (
    "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001",
    "SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001",
    "SUSPECT.AGENT.SKILL_CLAIM_MISMATCH.001",
    "SUSPECT.AGENT.SKILL_DECODE_RUN.001",
    "SUSPECT.AGENT.SKILL_DISGUISED_ARCHIVE.001",
    "SUSPECT.AGENT.SKILL_HOOK_FETCH.001",
    "SUSPECT.AGENT.SKILL_RUNS_INPUT.001",
    "SUSPECT.AGENT.SKILL_LISTENER.001",
)
_CAPABILITY: Final = (
    "SUSPECT.MCP.HANDLER_SHELL.001",
    "SUSPECT.MCP.SHELL_LAUNCH.001",
    "SUSPECT.MCP.CONTAINER_HOST_ACCESS.001",
    "POLICY.AGENT.MCP_BROAD_SCOPE.001",
    "POLICY.AGENT.WILDCARD_PERMISSION.001",
    "POLICY.AGENT.WIDE_DIRECTORY.001",
)
_LOOKALIKE: Final = (
    "SUSPECT.MCP.LOOKALIKE.001",
    "SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001",
)
_TOOL_LIST: Final = ("SUSPECT.MCP.TOOLS_CHANGED.001",)


class ReasonMap:
    TABLE: ClassVar[dict[str, str]] = {
        **dict.fromkeys(_TOOL_POISONING, "R600"),
        **dict.fromkeys(_SKILL_ATTACK, "R601"),
        **dict.fromkeys(_CAPABILITY, "R602"),
        **dict.fromkeys(_TOOL_LIST, "R604"),
        **dict.fromkeys(_LOOKALIKE, "R504"),
    }

    @classmethod
    def of(cls, rule_id: str) -> str | None:
        """The code the scanner rule `rule_id` has of its own, or None."""
        return cls.TABLE.get(rule_id)


__all__ = ["ReasonMap"]
