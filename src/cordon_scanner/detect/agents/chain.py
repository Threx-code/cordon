"""The agent chain: instruction files, agent settings, MCP configurations and AI agents in CI.

Coding agents read files a repository ships and act on them with the developer's rights, and in
CI with the pipeline's. Each file below is therefore an execution vector, the same class as a
`postinstall` script or a `.vscode/tasks.json`, and none of them is code a compiler checks.
Everything here is read statically: nothing is started, installed or connected to.

    A1  instruction files      CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules/**,
                               copilot-instructions.md, .windsurfrules, .clinerules, SKILL.md
    A2  agent settings         .claude/settings*.json hooks, wildcard permissions,
                               bypass modes; VS Code auto-approve
    A3  MCP configurations     .mcp.json, .cursor/mcp.json, .vscode/mcp.json, gemini settings,
                               claude_desktop_config.json
    A6  AI agents in CI        agent actions triggered by text an outsider writes, with secrets
                               or a write token in scope

## Confidence is split, on purpose

Hidden characters in an instruction file (zero-width, bidirectional, Unicode Tag, variation
selectors) have no reason to be there and are reported HIGH: they are how a "rules file
backdoor" hides an instruction from the person reviewing it. Visible text that tells an agent to
ignore its instructions or run a command is instruction-LIKE, and wording is not proof, so it is
MEDIUM and does not fail the default gate.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents.autorun import AUTORUN_PATHS
from cordon_scanner.detect.agents.ci_workflows import WorkflowFindings
from cordon_scanner.detect.agents.extension_files import ExtensionFileFindings
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.instruction_files import InstructionFileFindings
from cordon_scanner.detect.agents.instructions import InstructionText
from cordon_scanner.detect.agents.mcp_servers.findings import McpServerFindings
from cordon_scanner.detect.agents.mcp_servers.source import (
    MCP_SDK,
    SERVER_SOURCE_SUFFIXES,
)
from cordon_scanner.detect.agents.paths import (
    AGENT_SETTINGS_PATHS,
    BREWFILE_PATHS,
    CODEX_CONFIG_PATHS,
    COMMAND_PATHS,
    EXTENSION_PATHS,
    GITPOD_PATHS,
    INSTRUCTION_PATHS,
    MARKETPLACE_PATHS,
    MCP_PATHS,
    VSCODE_SETTINGS_PATHS,
    VSIX_MANIFEST,
    WORKFLOW_PATHS,
    AgentPaths,
)
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.detect.agents.settings_files import SettingsFileFindings
from cordon_scanner.detect.agents.skills import SkillScripts
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation.models import (
    Category,
    Finding,
)
from cordon_scanner.foundation.paths import ContainerPaths

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

_SKILL_SCRIPT_SUFFIXES: Final = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".rb")

#: A claim of priority over other tools in general -- not "prefer this tool over WebFetch", which
#: names the one it replaces, and not "call this tool first", which orders a workflow.
_PRIORITY_CLAIM: Final = re.compile(
    r"(?i)\b(?:should|must)\s+(?:always\s+)?be\s+(?:preferred|chosen|selected|prioriti[sz]ed)\s+"
    r"(?:first\s+)?(?:over|ahead\s+of|instead\s+of|rather\s+than)\s+(?:any\s+|all\s+)?(?:other"
    r"|adjacent|generic|alternative|competing|similar|existing)\b[^.\n]{0,80}\b(?:servers?|tools?"
    r"|plugins?|skills?)\b|\bprefer\s+this\s+(?:server|tool|skill|plugin)\s+first\b"
)

_DETECTOR_VOCABULARY: Final = re.compile(
    r"(?i)\b(?:detect(?:ion|or|s)?|scanner|signatures?|heuristics?)\b"
)

#: Package-manager config naming where installs come from, in code an agent runs: a literal URL, or
#: `${X}` in the no-space config syntax (not PowerShell's `registry = $registry`). No tool needs it.
_INSTALL_REDIRECT: Final = re.compile(
    r"(?m)\b(?:(?:extra-)?index-url|registry)(?:\s*=\s*https?://|=\$\{?\w)|npmRegistryServer\s*:"
    r"|^\s*registry\s+\"(?:https?://|\$\{?\w)|config\s+set\s+(?:global\.)?(?:index-url|registry)\b"
)


_HIDDEN_DIRECTIVE_DOCS: Final = (
    ".md",
    ".mdc",
    ".markdown",
    ".mdx",
    ".rst",
    ".txt",
    ".html",
    ".htm",
)


class AgentChainDetector(BaseDetector):
    """Agent instruction files, agent settings, MCP configurations and AI agents in CI."""

    id = AgentFinding.DETECTOR
    version = "0.1.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY, Category.VULNERABLE}
    )
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit) or unit.content.is_binary:
            return ()
        path = (
            unit.content.path.rpartition("!")[2] if "!" in unit.content.path else unit.content.path
        )
        findings: list[Finding] = []
        if AgentPaths._paths_match(path, INSTRUCTION_PATHS):
            findings.extend(InstructionFileFindings.instructions(unit, ctx))
        if AgentPaths._paths_match(path, AGENT_SETTINGS_PATHS):
            findings.extend(SettingsFileFindings.agent_settings(unit, ctx))
        if AgentPaths._paths_match(path, VSCODE_SETTINGS_PATHS):
            findings.extend(SettingsFileFindings.vscode_settings(unit, ctx))
        if AgentPaths._paths_match(path, MCP_PATHS):
            findings.extend(McpServerFindings.mcp(unit, ctx))
        if AgentPaths._paths_match(path, WORKFLOW_PATHS):
            findings.extend(WorkflowFindings.workflow(unit, ctx))
        if AgentPaths._paths_match(path, AUTORUN_PATHS):
            findings.extend(SettingsFileFindings.autorun(unit, ctx))
        if AgentPaths._paths_match(path, CODEX_CONFIG_PATHS):
            findings.extend(SettingsFileFindings.codex_config(unit, ctx))
        if AgentPaths._paths_match(path, MARKETPLACE_PATHS):
            findings.extend(SettingsFileFindings.marketplace(unit, ctx))
        if AgentPaths._paths_match(path, COMMAND_PATHS):
            findings.extend(SettingsFileFindings.command_permissions(unit, ctx))
        if AgentPaths._paths_match(path, EXTENSION_PATHS):
            findings.extend(ExtensionFileFindings.extension_recommendations(unit, ctx))
        if AgentPaths._paths_match(path, GITPOD_PATHS):
            findings.extend(ExtensionFileFindings.gitpod_extensions(unit, ctx))
        if AgentPaths._paths_match(path, BREWFILE_PATHS):
            for identifier in dict.fromkeys(
                re.findall(r"""(?m)^\s*vscode\s+["']([^"']+)["']""", unit.content.text)
            ):
                findings.extend(
                    ExtensionFileFindings.judge_extension(identifier, unit, ctx, recommended=True)
                )
        if path == VSIX_MANIFEST and ".vsix!" in unit.content.path.lower():
            findings.extend(ExtensionFileFindings.vsix_manifest(unit, ctx))
        if path.endswith(SERVER_SOURCE_SUFFIXES) and MCP_SDK.search(unit.content.text):
            findings.extend(McpServerFindings.server_source(unit, ctx))
        if path.lower().endswith(_SKILL_SCRIPT_SUFFIXES) and SkillScripts.in_skill(
            unit.content.path, ctx
        ):
            findings.extend(InstructionFileFindings.skill_script(unit, ctx))
        if (
            path.lower().endswith(_HIDDEN_DIRECTIVE_DOCS)
            or unit.content.path in ctx.agent_run_paths
        ):
            found = InstructionText.hidden_directive(unit.content.text)
            if found is not None and (
                path.lower().endswith(_HIDDEN_DIRECTIVE_DOCS)
                # In code, a detector's own sample of the attack -- a scanner's test string.
                or not _DETECTOR_VOCABULARY.search(unit.content.text)
            ):
                start, end = InstructionText._byte_span(unit.content.text, found)
                findings.append(
                    AgentFinding.finding(
                        "SUSPECT.AGENT.HIDDEN_DIRECTIVE.001", unit, ctx, start, end
                    )
                )
            redirect = (
                _INSTALL_REDIRECT.search(unit.content.text)
                if unit.content.path in ctx.agent_run_paths
                else None
            )
            if redirect is not None:
                start, end = InstructionText._byte_span(unit.content.text, redirect)
                findings.append(
                    AgentFinding.finding(
                        "SUSPECT.AGENT.INSTALL_REDIRECT.001", unit, ctx, start, end
                    )
                )
            claim = _PRIORITY_CLAIM.search(unit.content.text)
            if claim is not None:
                start, end = InstructionText._byte_span(unit.content.text, claim)
                findings.append(
                    AgentFinding.finding(
                        "SUSPECT.AGENT.TOOL_PRIORITY_CLAIM.001", unit, ctx, start, end
                    )
                )
        if ContainerPaths.basename(path).lower() == "readme.md" and SkillScripts.beside_skill(
            unit.content.path, ctx
        ):
            findings.extend(InstructionFileFindings.skill_readme(unit, ctx))
        return findings

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return tuple(
            DeclaredRule(
                id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                detector=AgentChainDetector.id,
                message=rule.message,
                remediation=rule.remediation,
                references=rule.references,
            )
            for rule in RULES.values()
        )

    # -- A1 ------------------------------------------------------------------------------

    # -- A2 ------------------------------------------------------------------------------

    # -- A3, and A4 offline ----------------------------------------------------------------

    # -- A6 ------------------------------------------------------------------------------

    # -- A5: editor extensions ---------------------------------------------------------------

    # -- Construction ----------------------------------------------------------------------


__all__ = ["AgentChainDetector"]
