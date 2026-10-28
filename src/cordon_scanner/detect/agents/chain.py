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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation.models import (
    Category,
    Finding,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import ScanContext, Unit
from cordon_scanner.detect.agents.extension_files import ExtensionFileFindings
from cordon_scanner.detect.agents.extensions import ExtensionNames
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
from cordon_scanner.detect.agents.rule_catalogue import RULES, AgentRules
from cordon_scanner.detect.agents.settings_files import SettingsFileFindings
from cordon_scanner.detect.agents.skills import SkillScripts

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


_OUTPUT_TO_COMMENT: Final = re.compile(
    r"(?m)\bgh\s+(?:pr|issue)\s+comment\b|\bcreateComment\s*\(|\buse_sticky_comment\s*:\s*true"
    r"|\bpeter-evans/create-or-update-comment\b|\bmarocchino/sticky-pull-request-comment\b"
)

_ALLOWED_TOOLS_SET: Final = re.compile(
    r"(?i)allowed_tools|allowedTools|--allowedTools|claude_args\s*:"
)

_UNTRUSTED_TRIGGERS: Final = (
    "issues",
    "issue_comment",
    "pull_request_target",
    "pull_request_review_comment",
    "pull_request_review",
    "discussion",
    "discussion_comment",
)

_UNTRUSTED_TEXT: Final = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|comment\.body|review\.body|pull_request\.(?:title|body|head\.ref)"
    r"|discussion\.(?:title|body)|head_commit\.message)\s*\}\}"
)

_TRUSTED_GATE: Final = re.compile(
    r"author_association\s*(?:==|!=|,)|contains\(\s*fromJSON\([^)]*(?:OWNER|MEMBER|COLLABORATOR)"
    r"|github\.actor\s*==|github\.event\.(?:comment|issue|review)\.user\.login\s*=="
    r"|allowed_(?:bots|non_write_users)"
)

_WRITE_PERMISSION: Final = re.compile(
    r"^\s*(?:contents|pull-requests|issues|actions|packages|id-token|workflows|deployments|statuses)\s*:\s*write\b"
    r"|^\s*permissions\s*:\s*write-all\b",
    re.M,
)

_BROAD_TOOLS: Final = re.compile(
    r"""(?i)(?:allowed_tools|allowedTools|--allowedTools)[^\n]{0,80}Bash(?:\(\s*\*?\s*\))?(?:["',\s]|$)"""
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
            findings.extend(self._workflow(unit, ctx))
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

    """Claude Code settings whose value is a shell command the agent runs itself."""

    # -- A3, and A4 offline ----------------------------------------------------------------

    # -- A6 ------------------------------------------------------------------------------

    def _workflow(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        text = unit.content.text
        uses = list(re.finditer(r"(?m)^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w./-]+?)@([\w.\-]+)", text))
        known = AgentRules.agent_actions()
        agents = [m for m in uses if m.group(1).lower() in known]
        if not agents:
            return
        for match in agents:
            action, pin = match.group(1).lower(), match.group(2)
            fixed = known[action][1]
            version = ExtensionNames._semver(pin)
            if fixed and (
                (version is not None and version < fixed) or pin.lower() in ("beta", "v0")
            ):
                start, end = InstructionText._byte_span(text, match)
                yield AgentFinding.finding(
                    "VULNERABLE.AGENT.ACTION_VERSION.001",
                    unit,
                    ctx,
                    start,
                    end,
                    message=RULES["VULNERABLE.AGENT.ACTION_VERSION.001"].message
                    + f" {match.group(1)}@{pin} is below {'.'.join(map(str, fixed))}.",
                )

        injected = _UNTRUSTED_TEXT.search(text)
        if injected is not None:
            start, end = InstructionText._byte_span(text, injected)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.CI_PROMPT_INJECTION.001", unit, ctx, start, end
            )

        triggers = InstructionText._triggers(text)
        untrusted = sorted(set(triggers) & set(_UNTRUSTED_TRIGGERS))
        if not untrusted or _TRUSTED_GATE.search(text):
            return
        secrets = "${{ secrets." in text.replace("${{secrets.", "${{ secrets.")
        writes = _WRITE_PERMISSION.search(text) is not None or not re.search(
            r"(?m)^\s*permissions\s*:", text
        )
        broad = _BROAD_TOOLS.search(text) is not None
        unlisted = _ALLOWED_TOOLS_SET.search(text) is None
        comments = _OUTPUT_TO_COMMENT.search(text) is not None
        if not (secrets or writes):
            return
        what = [f"triggered by {', '.join(untrusted)}"]
        if secrets:
            what.append("with secrets in scope")
        if writes:
            what.append("with a token that can write")
        if broad:
            what.append("and unrestricted shell access for the agent")
        elif unlisted:
            what.append(
                "with no tool allow-list, so the agent's own defaults decide what it may run"
            )
        if comments:
            what.append(
                "and its output posted back as a comment, a channel an injected agent can write through"
            )
        first = agents[0]
        start, end = InstructionText._byte_span(text, first)
        rule = RULES["SUSPECT.AGENT.CI_UNTRUSTED_TRIGGER.001"]
        yield AgentFinding.finding(
            rule.rule_id,
            unit,
            ctx,
            start,
            end,
            message=f"{rule.message} Here: {known[first.group(1).lower()][0]} {'; '.join(what)}.",
            severity=Severity.CRITICAL if (secrets and writes and broad) else None,
        )

    # -- A5: editor extensions ---------------------------------------------------------------

    # -- Construction ----------------------------------------------------------------------


__all__ = ["AgentChainDetector"]
