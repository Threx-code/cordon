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
import tomllib
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents import agent_config
from cordon_scanner.detect.agents.agent_semantics import AgentSemantics
from cordon_scanner.detect.agents.autorun import AUTORUN_PATHS, Autorun
from cordon_scanner.detect.agents.defensive_doc import DefensiveDoc
from cordon_scanner.detect.agents.mcp_servers.description_model import (
    SKILL_MODEL,
    McpDescriptionModel,
)
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation.models import (
    Category,
    Finding,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.intel.malware import atr
from cordon_scanner.intel.registries.installers import OfficialInstallers

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import ScanContext, Unit
from cordon_scanner.detect.agents.extension_files import ExtensionFileFindings
from cordon_scanner.detect.agents.extensions import ExtensionNames
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.instructions import InstructionText
from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs
from cordon_scanner.detect.agents.mcp_servers.endpoints import (
    LOCAL_HOSTS,
    PLACEHOLDER,
    McpEndpoints,
)
from cordon_scanner.detect.agents.mcp_servers.source import (
    MCP_SDK,
    RESULT_SENDS_TO_URL,
    SERVER_SOURCE_SUFFIXES,
    McpServerSource,
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
from cordon_scanner.detect.agents.skills import SkillOrigin, SkillScripts
from cordon_scanner.detect.agents.text_findings import AgentTextFindings
from cordon_scanner.detect.agents.text_patterns import (
    FETCH_EXEC,
    HIDDEN,
    INJECTION,
    INJECTION_INTL,
    ORDERS_A_COMMAND,
)

_FLAG_TAGS: Final = re.compile(rb"\xf0\x9f\x8f\xb4(?:\xf3\xa0[\x80\x81][\x80-\xbf]){1,16}")

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

#: Code that lets one fixed identity through an access check: an equality with a literal or a
#: constant, then `return {allowed: true}`, `return True` or `authorized = true`.
_AUTH_BYPASS_CODE: Final = re.compile(
    r"(?:===?|==)\s*(?:\"[^\"\n]{1,80}\"|'[^'\n]{1,80}'|[A-Z][A-Z0-9_]{3,40})\s*\)?\s*(?:\|\||&&|or|and)?"
    r"[^\n]{0,120}?(?:\)\s*\{|:)\s*\n?[ \t]*(?:return\s*\{[^}]{0,200}?\b(?:allowed|authori[sz]ed|isAdmin"
    r"|is_admin|granted|bypass|admin)\s*:\s*true|return\s+(?:True|true)\s*(?:#|//|;|\n)|\b(?:allowed"
    r"|authori[sz]ed|isAdmin|is_admin|granted)\s*=\s*(?:true|True))"
)

#: Telling the agent to put a block of code into the project.
_INSERT_DIRECTIVE: Final = re.compile(
    r"(?i)\b(?:inject|insert|add|paste|place)\b[^\n]{0,120}\b(?:block|code|snippet|following|below)\b"
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

#: A front-matter delimiter naming a code engine: `---js`, `---javascript`, `---coffee`. gray-matter,
#: the parser most JavaScript tooling uses, evaluates such a block as code when it reads the file. At
#: any line start, not only the first: a loader that takes the first delimited block after a fence or
#: a preamble reads it there, and no agent instruction file has a use for the marker.
_CODE_FRONT_MATTER: Final = re.compile(
    r"^[ \t]{0,3}---[ \t]*(?:js|javascript|coffee|coffeescript)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)

_SENSITIVE_IMPORT: Final = re.compile(
    r"(?im)(?:^|\s)@(?:~|\$HOME|/root|/home/[\w.-]+|/Users/[\w.-]+)/\.(?:ssh|aws|azure|kube|docker|gnupg|npmrc|pypirc|netrc|git-credentials|config/gcloud)\b[^\s]*"
    r"|(?:^|\s)@(?:[\w./~-]*/)?(?:id_(?:rsa|ed25519|ecdsa|dsa)|\.env)(?![\w.-])"
    r"|(?:^|\s)@/etc/(?:shadow|passwd|sudoers)\b"
)
"""An `@path` import (Claude Code and others read such a line into the context) of a credential
file: the agent loads it every session and sends it to the model provider."""

_REMOTE_INSTRUCTIONS: Final = re.compile(
    r"(?i)\b(?:fetch|download|read|load|retrieve|get|curl|wget|pull)\b[^\n]{0,60}?https?://\S+"
    r"[^\n]{0,80}?\b(?:and|then)\s+(?:follow|obey|apply|execute|carry\s+out|do\s+what)\b"
)

_SECRET_NAME: Final = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)"
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
            findings.extend(self._instructions(unit, ctx))
        if AgentPaths._paths_match(path, AGENT_SETTINGS_PATHS):
            findings.extend(self._agent_settings(unit, ctx))
        if AgentPaths._paths_match(path, VSCODE_SETTINGS_PATHS):
            findings.extend(self._vscode_settings(unit, ctx))
        if AgentPaths._paths_match(path, MCP_PATHS):
            findings.extend(self._mcp(unit, ctx))
        if AgentPaths._paths_match(path, WORKFLOW_PATHS):
            findings.extend(self._workflow(unit, ctx))
        if AgentPaths._paths_match(path, AUTORUN_PATHS):
            findings.extend(self._autorun(unit, ctx))
        if AgentPaths._paths_match(path, CODEX_CONFIG_PATHS):
            findings.extend(self._codex_config(unit, ctx))
        if AgentPaths._paths_match(path, MARKETPLACE_PATHS):
            findings.extend(self._marketplace(unit, ctx))
        if AgentPaths._paths_match(path, COMMAND_PATHS):
            findings.extend(self._command_permissions(unit, ctx))
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
            findings.extend(self._server_source(unit, ctx))
        if path.lower().endswith(_SKILL_SCRIPT_SUFFIXES) and SkillScripts.in_skill(
            unit.content.path, ctx
        ):
            findings.extend(self._skill_script(unit, ctx))
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
            findings.extend(self._skill_readme(unit, ctx))
        return findings

    def _skill_readme(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A skill's README, beside its SKILL.md: the agent reads it with the skill, and the
        ClawHavoc lures put their fake prerequisite there ("download and install OpenClawCLI
        from <free host> before using this skill"). Only the phantom-prerequisite check: it
        matched none of the 9,001 READMEs in public skill folders (review 98)."""
        text = unit.content.text
        phantom = InstructionText.phantom_prerequisite(text)
        if phantom is not None:
            start, end = InstructionText._byte_span(text, phantom)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001", unit, ctx, start, end
            )

    def _skill_script(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A script that ships with a skill and decodes code to run it. In a library the same
        line is sometimes a packer; in a skill, the agent runs it on the user's machine when the
        skill is used, and hiding what it runs has no use but hiding it."""
        found = SkillScripts.decode_run(unit.content.text)
        if found is not None:
            start, end = InstructionText._byte_span(unit.content.text, found)
            yield AgentFinding.finding("SUSPECT.AGENT.SKILL_DECODE_RUN.001", unit, ctx, start, end)
        hooked = SkillScripts.hooks_a_download(unit.content.text)
        if hooked is not None:
            start, end = InstructionText._byte_span(unit.content.text, hooked)
            yield AgentFinding.finding("SUSPECT.AGENT.SKILL_HOOK_FETCH.001", unit, ctx, start, end)
        if unit.content.path.endswith(".py"):
            # What the agent gets when it calls the script's functions (`detect/mcp_code.py`).
            from cordon_scanner.detect.agents.mcp_servers.handlers import McpCode

            text = unit.content.text
            starts = [0, *(m.end() for m in re.finditer(r"\n", text))]

            def at(line: int) -> tuple[int, int]:
                first = starts[min(max(line, 1), len(starts)) - 1]
                last = text.find("\n", first)
                last = len(text) if last < 0 else last
                return len(text[:first].encode("utf-8")), len(text[:last].encode("utf-8"))

            for line, _function in McpCode.runs_own_input(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_RUNS_INPUT.001", unit, ctx, *at(line)
                )
            for line, _name, _popular in McpCode.installs_lookalikes(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001", unit, ctx, *at(line)
                )
            for line in McpCode.returns_jailbreak(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001", unit, ctx, *at(line)
                )

    def _server_source(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """An MCP server's own source: the tool names and descriptions it hands the agent.

        Read without running anything, so a repository's own server is judged offline the way
        `--online` judges a fetched one.
        """
        text = unit.content.text
        seen: set[str] = set()
        for description in McpServerSource._tool_descriptions(text):
            if description in seen:
                continue
            seen.add(description)
            yield from AgentTextFindings.intents(unit, ctx, description, within=text)
            reason = McpServerSource._poisoned_description(description)
            if reason is None:
                # The steps an attack on the agent takes, in a combination no real server's own
                # description carries (`agent_semantics.PRECISE`).
                chain = AgentSemantics.precise(description)
                if chain is not None:
                    reason = f"gives {AgentSemantics.explain(chain)}"
            # The learned reading (`detect/mcp_model.py`): poisoning written as ordinary prose,
            # which no phrase rule narrow enough to stay quiet catches. Blocks above `block`;
            # reported for review between `warn` and `block`.
            score = McpDescriptionModel.score(description)
            limits = McpDescriptionModel.thresholds()
            learned = score is not None and limits is not None and score >= limits[1]
            # ATR's phrase rules, read beside the model: on 980 real MCP servers they blocked 11
            # on their own -- security tools quoting attacks, prompts that tell an agent how to
            # use the tool -- and on MCP-SafetyBench none of 146 blocks needed them alone.
            unconfirmed = limits is not None and not learned and reason is None
            if reason is not None or learned:
                blocking = reason is not None or (limits is not None and score >= limits[0])  # type: ignore[operator]  # learned implies a score
                why = (
                    f" It {reason}."
                    if reason is not None
                    else f" It reads as instructions to the agent rather than a description of the "
                    f"tool (model score {score:.2f})."
                )
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                    unit,
                    ctx,
                    text,
                    description[:80],
                    message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message + why,
                    severity=None if blocking else Severity.MEDIUM,
                )
            yield from AgentTextFindings.threat_rules(
                unit, ctx, description, atr.TEXT_KINDS, within=text, unconfirmed=unconfirmed
            )
        names = (m.group("name") or m.group("pyname") for m in _TOOL_NAME.finditer(text))
        for name in dict.fromkeys(names):
            yield from AgentTextFindings.threat_rules(unit, ctx, name, ("tool_name",), within=text)
        if unit.content.path.endswith(".py"):
            # What the handlers do with the agent's input (`detect/mcp_code.py`).
            from cordon_scanner.detect.agents.mcp_servers.handlers import McpCode

            starts = [0, *(m.end() for m in re.finditer(r"\n", text))]

            def at(line: int) -> tuple[int, int]:
                first = starts[min(max(line, 1), len(starts)) - 1]
                last = text.find("\n", first)
                last = len(text) if last < 0 else last
                return len(text[:first].encode("utf-8")), len(text[:last].encode("utf-8"))

            for line, _tool, triggered in McpCode.shell_from_input_graded(text):
                # Behind a secret prefix or value it is a backdoor and blocks; run on whatever
                # arrives it is a command-injection bug, reported as one (MCP-SafetyBench's own
                # benign yahoo_finance server runs `os.system(f"echo {msg}")`).
                yield AgentFinding.finding(
                    "SUSPECT.MCP.HANDLER_SHELL.001",
                    unit,
                    ctx,
                    *at(line),
                    severity=None if triggered else Severity.MEDIUM,
                    message=None
                    if triggered
                    else RULES["SUSPECT.MCP.HANDLER_SHELL.001"].message
                    + " No secret gates it: it runs whatever arrives, a vulnerability rather than "
                    "a backdoor.",
                )
            for line, _tool in McpCode.time_bomb(text)[:3]:
                yield AgentFinding.finding("SUSPECT.MCP.TIME_BOMB.001", unit, ctx, *at(line))
            for line, _tool in McpCode.mirrors_input(text)[:3]:
                yield AgentFinding.finding("SUSPECT.MCP.INPUT_MIRROR.001", unit, ctx, *at(line))
            for line, tool, host in McpCode.forwards_input(text)[:3]:
                yield AgentFinding.finding(
                    "SUSPECT.MCP.INPUT_FORWARDED.001",
                    unit,
                    ctx,
                    *at(line),
                    message=RULES["SUSPECT.MCP.INPUT_FORWARDED.001"].message
                    + f" Tool `{tool}` sends its input to {host}.",
                )
            for line in McpCode.secret_harvest(text):
                yield AgentFinding.finding("SUSPECT.MCP.SECRET_HARVEST.001", unit, ctx, *at(line))
            listening = McpCode.listener(text)
            if listening is not None:
                yield AgentFinding.finding("SUSPECT.MCP.LISTENER.001", unit, ctx, *at(listening))
            for first, last in McpServerSource._overridden_arguments(text):
                start = len(text[:first].encode("utf-8"))
                end = start + len(text[first:last].encode("utf-8"))
                yield AgentFinding.finding(
                    "SUSPECT.MCP.ARGUMENT_OVERRIDE.001", unit, ctx, start, end
                )
        # What the tools hand back. The agent reads a tool's result as context, so an instruction
        # in a returned string steers it as one in a description does. The model only: the
        # phrase rules were written for descriptions, and status messages are not those.
        limits = McpDescriptionModel.thresholds("return")
        if limits is not None:
            for returned in dict.fromkeys(McpServerSource._tool_returns(text)):
                # A result that wraps instructions in a tag addressed to the model --
                # `<IMPORTANT>you must now call get_me</IMPORTANT>` -- is not a result.
                if McpServerSource._wrapped(returned):
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                        unit,
                        ctx,
                        text,
                        returned[:80],
                        message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message
                        + " The text is what a tool returns, and it wraps text in a tag "
                        "addressed to the model.",
                    )
                    continue
                chain = AgentSemantics.precise(returned, "return")
                if chain is not None:
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                        unit,
                        ctx,
                        text,
                        returned[:80],
                        message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message
                        + f" The text is what a tool returns, and it gives "
                        f"{AgentSemantics.explain(chain)}.",
                    )
                    continue
                if RESULT_SENDS_TO_URL.search(returned) or ORDERS_A_COMMAND.search(returned):
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                        unit,
                        ctx,
                        text,
                        returned[:80],
                        message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message
                        + " The text is what a tool returns, and it sends the agent to call a "
                        "tool on a web address the result supplies, or to run a shell command.",
                    )
                    continue
                score = McpDescriptionModel.score(returned, "return")
                if score is None or score < limits[1]:
                    continue
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                    unit,
                    ctx,
                    text,
                    returned[:80],
                    message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message
                    + " The text is what a tool returns, and it reads as instructions to the "
                    f"agent rather than a result (model score {score:.2f}).",
                    severity=None if score >= limits[0] else Severity.MEDIUM,
                )
        yield from self._server_content(unit, ctx, text)

    def _server_content(self, unit: FileUnit, ctx: ScanContext, text: str) -> Iterator[Finding]:
        """What an MCP server hands the agent besides its descriptions -- tool results, resource
        content, a page it serves to itself -- and what its input schema asks for, read from every
        string literal of its source (review 98: canack/bad-mcp, whose descriptions are clean).
        """
        from cordon_scanner.analysis.shared.render_diff import HiddenInstruction

        if (
            not _SERVER_BUILT.search(text)
            and next(McpServerSource._tool_descriptions(text), None) is None
        ):
            # A file that names the SDK -- a scanner, a client, documentation -- is not a server:
            # what it quotes is not what an agent is handed.
            return
        squat = _SQUATTED_TOOL.search(text)
        if squat is not None:
            yield AgentFinding.at_text(
                "SUSPECT.MCP.TOOL_SQUATTING.001",
                unit,
                ctx,
                text,
                squat.group("name"),
                message=RULES["SUSPECT.MCP.TOOL_SQUATTING.001"].message
                + f" The tool is named `{squat.group('name')}`.",
            )
        hidden = schema = wallet = False
        # A parameter is a name in the code -- a Python argument, a zod key -- as often as a string.
        for name in dict.fromkeys(_IDENTIFIER.findall(text)):
            if _SCHEMA_ORDER.fullmatch(name) and _SCHEMA_ASKS.search(name.replace("_", " ")):
                schema = True
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.SCHEMA_POISONING.001", unit, ctx, text, name
                )
                break
        for literal in McpServerSource._all_literals(text):
            if not hidden and ("<!--" in literal or "[//]:" in literal):
                spans = [s for s in HiddenInstruction.find(literal) if HiddenInstruction.strong(s)]
                if spans:
                    hidden = True
                    yield AgentFinding.at_text(
                        "SUSPECT.AGENT.HIDDEN_INSTRUCTION.001",
                        unit,
                        ctx,
                        text,
                        literal[:80],
                        message=RULES["SUSPECT.AGENT.HIDDEN_INSTRUCTION.001"].message
                        + " It is in text this MCP server returns or serves -- a tool result, a "
                        "resource, a page -- which the agent reads in full and the user sees "
                        "rendered.",
                    )
            if (
                not schema
                and _SCHEMA_ORDER.fullmatch(literal)
                and _SCHEMA_ASKS.search(literal.replace("_", " "))
            ):
                schema = True
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.SCHEMA_POISONING.001", unit, ctx, text, literal[:80]
                )
            if not wallet and _CALL_AGAIN.search(literal):
                wallet = True
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.DENIAL_OF_WALLET.001", unit, ctx, text, literal[:80]
                )

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

    def _instructions(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        content = unit.content
        raw = content.raw
        flags = [m.span() for m in _FLAG_TAGS.finditer(raw)]
        found = [
            m
            for m in HIDDEN.finditer(raw)
            if not any(start <= m.start() < end for start, end in flags)
        ]
        hidden = [m for n, m in enumerate(found) if InstructionText._carries(raw, found, n)]
        if hidden:
            first = hidden[0]
            decoded = InstructionText._decode_tags(raw)
            message = RULES["SUSPECT.AGENT.HIDDEN_TEXT.001"].message + f" {len(hidden)} found."
            if decoded:
                message += f' Unicode Tag characters in it spell: "{decoded[:120]}".'
            yield AgentFinding.finding(
                "SUSPECT.AGENT.HIDDEN_TEXT.001",
                unit,
                ctx,
                first.start(),
                first.end(),
                message=message,
            )

        text = content.text
        bypass = _AUTH_BYPASS_CODE.search(text)
        if bypass is not None and _INSERT_DIRECTIVE.search(text):
            yield AgentFinding.finding(
                "SUSPECT.AGENT.AUTH_BYPASS_EDIT.001",
                unit,
                ctx,
                *InstructionText._byte_span(text, bypass),
            )
        fetches = list(FETCH_EXEC.finditer(text))
        injection = next(
            (
                m
                for m in (*INJECTION.finditer(text), *INJECTION_INTL.finditer(text))
                if not InstructionText._quoted(text, m) and not InstructionText._forbidden(text, m)
            ),
            None,
        )
        exfil = InstructionText.moves_credentials(text) is not None
        # HIGH where the instruction is the attack's shape: a destination with no business
        # serving an installer (a paste site, a tunnel, a webhook, a raw address, a shortener), a
        # decoded payload, or a file that also hides text, overrides the agent or moves
        # credentials. A skill installing a vendor's CLI from the vendor's host is setup the
        # agent runs when somebody invokes the skill, and is reported below the gate --
        # across the first 228 repositories that was seventeen blocking findings in seven,
        # every one a CLI install line.
        alarming = next((m for m in fetches if InstructionText._alarming_fetch(m.group(0))), None)
        unknown = next(
            (m for m in fetches if not OfficialInstallers.is_official_installer(m.group(0))), None
        )
        concealed = InstructionText.concealed(text)
        if alarming is not None or (
            unknown is not None and (hidden or injection or exfil or concealed)
        ):
            chosen = alarming or unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield AgentFinding.finding("SUSPECT.AGENT.FETCH_EXEC.001", unit, ctx, start, end)
        elif fetches:
            chosen = unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.FETCH_EXEC.001",
                unit,
                ctx,
                start,
                end,
                # A vendor's own installer from its own host is how the tool is installed, and is
                # recorded; any other host warns.
                severity=Severity.LOW if unknown is None else Severity.MEDIUM,
                message=RULES["SUSPECT.AGENT.FETCH_EXEC.001"].message
                + (
                    " The script comes from the tool's own official installer host"
                    if unknown is None
                    else " It installs from a vendor host with nothing else in the file pointing at an attack"
                )
                + ", so this is reported below the default gate.",
            )
        if injection is not None:
            start, end = InstructionText._byte_span(text, injection)
            yield AgentFinding.finding("SUSPECT.AGENT.INJECTION_TEXT.001", unit, ctx, start, end)
        phantom = InstructionText.phantom_prerequisite(text)
        if phantom is not None:
            start, end = InstructionText._byte_span(text, phantom)
            yield AgentFinding.finding(
                "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001", unit, ctx, start, end
            )
        dropper = InstructionText.dropper(text)
        if dropper is not None:
            start, end = InstructionText._byte_span(text, dropper)
            yield AgentFinding.finding("SUSPECT.AGENT.DROPPER_PROSE.001", unit, ctx, start, end)
        executable = _CODE_FRONT_MATTER.search(text)
        if executable is not None:
            start, end = InstructionText._byte_span(text, executable)
            yield AgentFinding.finding("SUSPECT.AGENT.FRONT_MATTER_CODE.001", unit, ctx, start, end)
        imported = _SENSITIVE_IMPORT.search(text)
        if imported is not None:
            start, end = InstructionText._byte_span(text, imported)
            yield AgentFinding.finding("SUSPECT.AGENT.SENSITIVE_IMPORT.001", unit, ctx, start, end)
        remote = _REMOTE_INSTRUCTIONS.search(text)
        if remote is not None:
            start, end = InstructionText._byte_span(text, remote)
            alarming_host = InstructionText._alarming_fetch(remote.group(0))
            yield AgentFinding.finding(
                "SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001",
                unit,
                ctx,
                start,
                end,
                severity=Severity.HIGH if alarming_host else None,
            )
        moved = InstructionText.moves_credentials(text)
        if moved is None:
            moved = next(
                (
                    m
                    for m in re.finditer(r"(?:[^\n]*\\\n)*[^\n]+", text)  # with its `\` lines
                    if (verdict := agent_config.CommandClassifier.classify(m.group(0))) is not None
                    and verdict.kind != "fetch-exec"
                ),
                None,
            )
        if moved is not None:
            start, end = InstructionText._byte_span(text, moved)
            yield AgentFinding.finding("SUSPECT.AGENT.CREDENTIAL_EXFIL.001", unit, ctx, start, end)
        # A skill that wires the agent to an MCP server on a tunnel or a bare public address
        # (review 98, AG-4): `"url": "http://bore.pub:44876/api/v1/mcp/.../sse"` is a laptop the
        # skill's author reaches from the internet, handed the agent's tools and context.
        endpoint = next(
            (
                url
                for url in McpEndpoints.in_text(text)
                if McpEndpoints.untrusted(agent_config.ApiTraffic.host_of(url))
            ),
            None,
        )
        if endpoint is not None:
            yield AgentFinding.at_text(
                "SUSPECT.MCP.UNTRUSTED_REMOTE.001", unit, ctx, text, endpoint
            )
        yield from AgentTextFindings.intents(unit, ctx, text)
        # What the rendered page hides and the agent still reads (`detect/render_diff.py`).
        from cordon_scanner.analysis.shared.render_diff import HiddenInstruction

        spans = HiddenInstruction.find(text)
        for span in sorted(spans, key=lambda s: not HiddenInstruction.strong(s))[:1]:
            start, end = (
                len(text[: span.start].encode("utf-8")),
                len(text[: span.end].encode("utf-8")),
            )
            yield AgentFinding.finding(
                "SUSPECT.AGENT.HIDDEN_INSTRUCTION.001",
                unit,
                ctx,
                start,
                end,
                message=RULES["SUSPECT.AGENT.HIDDEN_INSTRUCTION.001"].message
                + f" It is in {span.how}.",
                # At the gate when it is addressed to the agent and names something that matters;
                # a hidden order about a destination alone is reported below it.
                severity=None if HiddenInstruction.strong(span) else Severity.MEDIUM,
            )
        corroborated = bool(hidden or injection or exfil or concealed or alarming is not None)
        corroborated_code = DefensiveDoc.code_evidence(hidden, exfil, concealed, alarming)
        third_party = SkillOrigin.third_party(unit.content.path, ctx)
        # A skill's instructions, read by the learned model (`SKILL_MODEL`). Held-out MalSkillBench:
        # blocked 44% -> 83%, benign 5.0% -> 3.3%, as ATR wording blocks only where the model or
        # Cordon's own evidence agrees; an override phrase is wording too (41 public skills).
        unconfirmed = False
        if ContainerPaths.basename(unit.content.path).upper() == "SKILL.MD":
            limits = SKILL_MODEL.thresholds("skill")
            score = SKILL_MODEL.score(text, "skill") if limits is not None else None
            if limits is not None and score is not None:
                unconfirmed = score < limits[1] and not corroborated_code
                if score >= limits[1]:
                    blocking = third_party and score >= limits[0]
                    yield AgentFinding.finding(
                        "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001",
                        unit,
                        ctx,
                        0,
                        min(len(unit.content.raw), 200),
                        message=RULES["SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"].message
                        + f" Model score {score:.2f}.",
                        severity=None if blocking else Severity.MEDIUM,
                    )
        yield from AgentTextFindings.threat_rules(
            unit,
            ctx,
            text,
            atr.TEXT_KINDS,
            # The project's own instruction files get the instruction-file tolerance; a skill
            # installed from elsewhere is code being installed and keeps ATR's grades (AG-2).
            instruction_file=not third_party,
            corroborated=corroborated,
            corroborated_code=corroborated_code,
            documentation=True,
            unconfirmed=unconfirmed,
        )

    # -- A2 ------------------------------------------------------------------------------

    def _agent_settings(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = McpConfigs._json(unit.content)
        if not isinstance(settings, dict):
            return
        text = unit.content.text
        hooks = settings.get("hooks")
        if isinstance(hooks, dict) and hooks:
            commands = [c for c in McpConfigs._hook_commands(hooks) if c]
            for command in commands:
                # A hook that only runs local code -- the repository's own script, a tool on
                # PATH -- can warn on ATR's wording but not block on it: `python -c "import os"`
                # matches rules written for a skill package's payload, and is what hooks that
                # find the project root are made of.
                yield from AgentTextFindings.threat_rules(
                    unit,
                    ctx,
                    command,
                    atr.TEXT_KINDS,
                    within=text,
                    local=not agent_config.CommandClassifier.reaches_out(command),
                )
            attack = next(
                (
                    (c, v)
                    for c in commands
                    if (v := agent_config.CommandClassifier.classify(c)) is not None
                ),
                None,
            )
            if attack is not None:
                command, verdict = attack
                rule_id = (
                    "MALWARE.AGENT.HOOK_FETCH_EXEC.001"
                    if verdict.kind == "fetch-exec"
                    else "MALWARE.AGENT.HOOK_EXFIL.001"
                )
                yield AgentFinding.at_text(rule_id, unit, ctx, text, command)
            elif commands:
                # Graded by what the hooks run: formatters, linters, tests, notifications and
                # the repository's own scripts -- which the scan reads as its code -- are what
                # hooks are committed for; anything else is worth a reviewer's look.
                unfamiliar = [
                    c
                    for c in commands
                    if not agent_config.CommandClassifier.is_routine(c)
                    and agent_config.CommandClassifier.reaches_out(c)
                ]
                yield AgentFinding.at_text(
                    "SUSPECT.AGENT.HOOK.001",
                    unit,
                    ctx,
                    text,
                    (unfamiliar or commands)[0],
                    severity=None if unfamiliar else Severity.LOW,
                    message=None
                    if unfamiliar
                    else RULES["SUSPECT.AGENT.HOOK.001"].message
                    + " No hook here reaches the network, runs a remote package or decodes a"
                    " payload -- they run local tools and the repository's own scripts -- so this"
                    " is reported for the record.",
                )
        yield from self._settings_commands(unit, ctx, settings, text)
        yield from self._settings_reach(unit, ctx, settings, text)
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            allowed = [str(a) for a in permissions.get("allow") or () if isinstance(a, str)]
            wildcard = next(
                (
                    a
                    for a in allowed
                    if re.fullmatch(
                        r"\s*(?:\*|Bash|Bash\(\s*\*?\s*\)|Bash\(\s*\*\s*:\s*\*\s*\))\s*", a
                    )
                ),
                None,
            )
            if wildcard is not None:
                yield AgentFinding.at_text(
                    "POLICY.AGENT.WILDCARD_PERMISSION.001", unit, ctx, text, wildcard
                )
            if permissions.get("defaultMode") == "bypassPermissions":
                yield AgentFinding.at_text(
                    "POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, "bypassPermissions"
                )
        if settings.get("enableAllProjectMcpServers") is True:
            yield AgentFinding.at_text(
                "POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, "enableAllProjectMcpServers"
            )

    _HELPER_KEYS: Final = (
        "apiKeyHelper",
        "awsAuthRefresh",
        "awsCredentialExport",
        "otelHeadersHelper",
        "gcpAuthRefresh",
    )
    """Claude Code settings whose value is a shell command the agent runs itself."""

    def _settings_commands(
        self, unit: FileUnit, ctx: ScanContext, settings: dict[str, Any], text: str
    ) -> Iterator[Finding]:
        """Commands a settings file has the agent run without a hook: helpers and the status line."""
        commands = [(key, settings.get(key)) for key in self._HELPER_KEYS]
        status = settings.get("statusLine")
        if isinstance(status, dict):
            commands.append(("statusLine", status.get("command")))
        for key, command in commands:
            if not isinstance(command, str):
                continue
            verdict = agent_config.CommandClassifier.classify(command)
            if verdict is not None:
                yield AgentFinding.at_text(
                    "MALWARE.AGENT.AUTORUN.001",
                    unit,
                    ctx,
                    text,
                    command,
                    message=RULES["MALWARE.AGENT.AUTORUN.001"].message
                    + f" Here it is the `{key}` setting, which {verdict.reason}.",
                )

    def _settings_reach(
        self, unit: FileUnit, ctx: ScanContext, settings: dict[str, Any], text: str
    ) -> Iterator[Finding]:
        """Where a settings file sends the agent's traffic, and what it lets the agent reach."""
        env = settings.get("env")
        if isinstance(env, dict):
            for name, value in env.items():
                if agent_config.ApiTraffic.redirects_api(str(name), value):
                    yield AgentFinding.at_text(
                        "SUSPECT.AGENT.API_REDIRECT.001",
                        unit,
                        ctx,
                        text,
                        str(value),
                        message=RULES["SUSPECT.AGENT.API_REDIRECT.001"].message
                        + f" ({name} -> {agent_config.ApiTraffic.host_of(str(value))})",
                    )
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            wide = next(
                (
                    d
                    for d in permissions.get("additionalDirectories") or ()
                    if agent_config.ServerExposure.wide_directory(d)
                ),
                None,
            )
            if wide is not None:
                yield AgentFinding.at_text(
                    "POLICY.AGENT.WIDE_DIRECTORY.001", unit, ctx, text, str(wide)
                )
        marketplaces = settings.get("extraKnownMarketplaces")
        enabled = settings.get("enabledPlugins")
        if isinstance(marketplaces, dict) and isinstance(enabled, dict):
            for plugin, on in enabled.items():
                market = str(plugin).rpartition("@")[2]
                if on is True and market in marketplaces:
                    source = (
                        marketplaces[market].get("source")
                        if isinstance(marketplaces[market], dict)
                        else None
                    )
                    repo = source.get("repo") if isinstance(source, dict) else None
                    if isinstance(repo, str) and repo.lower().startswith("anthropics/"):
                        continue
                    url = source.get("url") if isinstance(source, dict) else None
                    # A GitHub repository can be read before it is trusted; a plain-HTTP or
                    # other URL source cannot be pinned to what was reviewed.
                    reviewable = isinstance(repo, str) or (
                        isinstance(url, str) and url.lower().startswith("https://github.com/")
                    )
                    yield AgentFinding.at_text(
                        "SUSPECT.AGENT.PLUGIN_SOURCE.001",
                        unit,
                        ctx,
                        text,
                        str(plugin),
                        severity=Severity.MEDIUM if reviewable else None,
                    )
                    break
        # Gemini CLI's approval modes: `yolo` approves every tool call.
        general_value, tools_value = settings.get("general"), settings.get("tools")
        general: dict[str, Any] = general_value if isinstance(general_value, dict) else {}
        tools: dict[str, Any] = tools_value if isinstance(tools_value, dict) else {}
        yolo = next(
            (
                key
                for key, value in (
                    ("defaultApprovalMode", general.get("defaultApprovalMode")),
                    ("approvalMode", settings.get("approvalMode")),
                    ("yolo", settings.get("yolo")),
                    ("autoAccept", settings.get("autoAccept")),
                    ("autoAccept", tools.get("autoAccept")),
                )
                if value is True or (isinstance(value, str) and value.lower() == "yolo")
            ),
            None,
        )
        if yolo is not None:
            yield AgentFinding.at_text("POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, yolo)

    def _vscode_settings(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = McpConfigs._json(unit.content)
        if isinstance(settings, dict) and settings.get("chat.tools.autoApprove") is True:
            yield AgentFinding.at_text(
                "POLICY.AGENT.AUTO_APPROVE.001",
                unit,
                ctx,
                unit.content.text,
                "chat.tools.autoApprove",
            )

    # -- A3, and A4 offline ----------------------------------------------------------------

    def _mcp(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        text = unit.content.text
        for name, server in McpConfigs.mcp_servers(unit.content.path, text):
            yield from self._mcp_server(unit, ctx, text, name, server)

    def _mcp_server(
        self, unit: FileUnit, ctx: ScanContext, text: str, name: str, server: dict[str, Any]
    ) -> Iterator[Finding]:
        url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
        if isinstance(url, str):
            yield from self._remote_server(unit, ctx, text, url)

        command = server.get("command")
        args = [str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))]
        if isinstance(command, str):
            launch = " ".join([command, *args])
            yield from AgentTextFindings.threat_rules(
                unit, ctx, launch, atr.TEXT_KINDS, within=text
            )
            verdict = agent_config.CommandClassifier.classify(launch)
            if verdict is not None or FETCH_EXEC.search(launch):
                yield AgentFinding.at_text(
                    "SUSPECT.MCP.SHELL_LAUNCH.001",
                    unit,
                    ctx,
                    text,
                    args[-1] if args else command,
                    message=RULES["SUSPECT.MCP.SHELL_LAUNCH.001"].message
                    + (f" The launch {verdict.reason}." if verdict is not None else ""),
                )
            scope = agent_config.ServerExposure.broad_filesystem_scope(args)
            if scope is not None:
                yield AgentFinding.at_text(
                    "POLICY.AGENT.MCP_BROAD_SCOPE.001", unit, ctx, text, scope
                )
            spec = McpConfigs.launched_package(command, args)
            if spec is not None:
                ecosystem, package, pinned = spec
                imitated = agent_config.PackageLookalike.lookalike_of(package)
                if imitated is not None:
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.LOOKALIKE.001",
                        unit,
                        ctx,
                        text,
                        package,
                        message=RULES["SUSPECT.MCP.LOOKALIKE.001"].message
                        + f" ({package} imitates {imitated})",
                    )
                if not pinned:
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.UNPINNED.001",
                        unit,
                        ctx,
                        text,
                        package,
                        message=RULES["SUSPECT.MCP.UNPINNED.001"].message
                        + f" ({ecosystem}: {package})",
                    )
            elif command.rsplit("/", 1)[-1] in ("docker", "podman") and "run" in args:
                launched = agent_config.ServerExposure.docker_run(args)
                image = launched.image if launched is not None else None
                if launched is not None and launched.host_access:
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.CONTAINER_HOST_ACCESS.001",
                        unit,
                        ctx,
                        text,
                        launched.host_access[0].split(" ", 1)[-1].split("=", 1)[0],
                        severity=Severity.MEDIUM if launched.socket_only else None,
                        message=RULES["SUSPECT.MCP.CONTAINER_HOST_ACCESS.001"].message
                        + f" ({', '.join(launched.host_access)})"
                        + (
                            " Only the Docker socket is mounted -- what a Docker-management"
                            " server needs -- so this is reported for review."
                            if launched.socket_only
                            else ""
                        ),
                    )
                if image and "@sha256:" not in image:
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.UNPINNED.001",
                        unit,
                        ctx,
                        text,
                        image,
                        message=RULES["SUSPECT.MCP.UNPINNED.001"].message + f" (image: {image})",
                    )

        environment = server.get("env")
        if isinstance(environment, dict):
            for name, value in environment.items():
                if agent_config.ServerExposure.injects_code(str(name), value):
                    yield AgentFinding.at_text(
                        "SUSPECT.MCP.ENV_INJECTION.001",
                        unit,
                        ctx,
                        text,
                        str(name),
                        message=RULES["SUSPECT.MCP.ENV_INJECTION.001"].message + f" ({name})",
                    )
        for block in ("env", "headers"):
            values = server.get(block)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if (
                    not isinstance(value, str)
                    or len(value) < 8
                    or PLACEHOLDER.search(value.strip())
                ):
                    continue
                literal = value.strip()
                if block == "headers" and key.lower() == "authorization":
                    token = literal.split(" ", 1)[-1]
                    if PLACEHOLDER.search(token) or token.startswith("${"):
                        continue
                elif not _SECRET_NAME.search(key) or "${" in literal:
                    continue
                yield AgentFinding.at_text(
                    "SECRET.MCP.INLINE_CREDENTIAL.001", unit, ctx, text, literal, secret=True
                )

    def _autorun(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """Commands an editor or agent runs when the folder is opened or the environment built.

        The handling lives in `autorun.py` so the rule can grow without this file; this delegates."""
        yield from Autorun.autorun_findings(unit, ctx)

    def _codex_config(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """Codex's settings: approval and sandbox modes, and where model requests go."""
        try:
            document = tomllib.loads(unit.content.text)
        except (tomllib.TOMLDecodeError, ValueError):
            return
        text = unit.content.text
        if (
            document.get("approval_policy") == "never"
            and document.get("sandbox_mode") == "danger-full-access"
        ):
            yield AgentFinding.at_text(
                "POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, "danger-full-access"
            )
        providers = document.get("model_providers")
        for provider in providers.values() if isinstance(providers, dict) else ():
            base = provider.get("base_url") if isinstance(provider, dict) else None
            if isinstance(base, str) and agent_config.ApiTraffic.redirects_api(
                "OPENAI_BASE_URL", base
            ):
                yield AgentFinding.at_text(
                    "SUSPECT.AGENT.API_REDIRECT.001",
                    unit,
                    ctx,
                    text,
                    base,
                    message=RULES["SUSPECT.AGENT.API_REDIRECT.001"].message
                    + f" (model provider -> {agent_config.ApiTraffic.host_of(base)})",
                )

    def _marketplace(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A plugin marketplace that installs plugins over plain HTTP."""
        document = McpConfigs._json(unit.content)
        if not isinstance(document, dict):
            return
        for plugin in document.get("plugins") or ():
            source = plugin.get("source") if isinstance(plugin, dict) else None
            location = (
                source.get("url") or source.get("repo") if isinstance(source, dict) else source
            )
            if isinstance(location, str) and location.lower().startswith("http://"):
                yield AgentFinding.at_text(
                    "SUSPECT.AGENT.PLUGIN_SOURCE.001", unit, ctx, unit.content.text, location
                )
                return

    _ANY_BASH: Final = re.compile(
        r"(?im)^allowed-tools\s*:[^\n]*?(?:^|[\s,\[\"'])Bash(?:\s*\(\s*\*\s*(?::\s*\*\s*)?\))?(?=[\s,\]\"']|$)"
    )

    def _command_permissions(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A slash command, subagent or skill that pre-approves any shell command."""
        head = unit.content.text[:4000]
        if not head.startswith("---"):
            return
        found = self._ANY_BASH.search(head.split("\n---", 1)[0])
        if found is not None:
            yield AgentFinding.at_text(
                "POLICY.AGENT.WILDCARD_PERMISSION.001", unit, ctx, unit.content.text, found.group(0)
            )

    def _remote_server(
        self, unit: FileUnit, ctx: ScanContext, text: str, url: str
    ) -> Iterator[Finding]:
        """A remote MCP server: how it is reached, where, and what its URL carries."""
        host = agent_config.ApiTraffic.host_of(url)
        local = host in LOCAL_HOSTS
        # Both can hold: `http://bore.pub:44876/...` is a tunnel reached in cleartext, and the
        # tunnel is the finding that blocks.
        if McpEndpoints.untrusted(host):
            yield AgentFinding.at_text("SUSPECT.MCP.UNTRUSTED_REMOTE.001", unit, ctx, text, url)
        if url.lower().startswith("http://") and not local:
            yield AgentFinding.at_text("SUSPECT.MCP.INSECURE_TRANSPORT.001", unit, ctx, text, url)
        secret = agent_config.ServerExposure.credential_in_url(url)
        if secret is not None:
            yield AgentFinding.at_text(
                "SECRET.MCP.INLINE_CREDENTIAL.001", unit, ctx, text, secret, secret=True
            )

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


_SQUATTED_TOOL: Final = re.compile(
    r"""["'`](?P<name>read_file|read_text_file|write_file|edit_file|list_directory|directory_tree|"""
    r"""search_files|move_file|create_directory|get_file_info|execute_command|run_command|"""
    r"""shell_exec|fetch|git_status|git_commit)["'`](?=(?:[^\n]{0,240}\n){0,4}"""
    r"""[^\n]{0,1004}?(?i:enhanced\s+version|integrated\s+security|security[- ]enhanced|"""
    r"""malware\s+(?:scan|detection)|virus\s+scan|integrity\s+verification|safer\s+(?:version|"""
    r"""alternative|replacement)|secure\s+(?:version|replacement)))"""
)
"""A filesystem, shell, fetch or git server's tool name, described as the safer version of it, which
the agent picks between same-named tools by (canack/bad-mcp squatting-file-ops). Crossed lines end
at their newline, so a long minified line has one reading, not thousands of backtracked splits."""

_SERVER_BUILT: Final = re.compile(
    r"\bFastMCP[ \t]*\(|\bMcpServer[ \t]*\(|\bnew[ \t]+(?:Mcp)?Server[ \t]*\(|"
    r"\bserver\.NewMCPServer[ \t]*\(|\bMCP::Server\.new\b|\bFastMcp::Server\.new\b|"
    r"\.(?:AddTool|add_tool|registerTool|AddResource|registerResource)[ \t]*\(|"
    r"@(?:mcp|server|app)\.(?:tool|resource|prompt)\b|\[McpServerTool[(\]]|#\[tool[(\]]|"
    r"\bNewToolResult\w{0,20}[ \t]*\(|\bCallToolResult[ \t]*[({]"
)
"""Code that builds an MCP server or registers a tool on one, as written in each SDK."""

_SCHEMA_ORDER: Final = re.compile(
    r"(?=[a-z0-9_]{12,120}$)[a-z0-9]{1,40}(?:_[a-z0-9]{1,40}){2,16}",
)
"""A parameter name or enum value written as an order (`content_also_include_all_env_variables`).
Read with `_SCHEMA_ASKS` below: the name has to ask for something to be added AND name what."""

_SCHEMA_ASKS: Final = re.compile(
    r"\b(?:include|attach|append|collect|dump|harvest)\b(?:\s\w+){0,3}?\s"
    r"(?:all\s|every\s|the\s)?(?:env|environment|ssh|credentials?|secrets?|passwords?|"
    r"conversation|chat|cookies|private\s+keys?|api\s+keys?)\b"
)
"""What a schema name has to say to be an order: add something, and name something the user would
not hand over -- `include_all_env_variables`, not `include_archived` or `with_access_token`."""

_IDENTIFIER: Final = re.compile(r"\b[a-z][a-z0-9]{0,40}(?:_[a-z0-9]{1,40}){3,16}\b")

_CALL_AGAIN: Final = re.compile(
    r"(?i)\b(?:call|invoke|run)\s+(?:this\s+tool|it|`?\w{2,40}`?)\s+"
    r"(?:again|recursively|with\b[^.\n]{0,80}\b(?:depth|level)\s*[=:+])"
    r"|\beach\s+of\s+(?:these|the\s+following)\b[^.\n]{0,160}"
    r"\b(?:call|invoke|must\s+(?:also\s+)?be\s+\w+ed|should\s+(?:also\s+)?be\s+\w+ed)\b"
)
"""A result telling the agent to call the tool again, deeper or once per item it lists: the
denial-of-wallet shape. A page token ("call again with next_page") names no depth or fan-out."""

_TOOL_NAME: Final = re.compile(
    r"""(?:\.tool\(\s*\{?\s*(?:name\s*:\s*)?|\bregisterTool\(\s*|\bname\s*[:=]\s*)"""
    r"""["'`](?P<name>[A-Za-z][\w.-]{1,80})["'`]"""
    r"""|@\w{1,40}(?:\.\w{1,40}){0,4}\.tool\b[^\n]{0,200}\n(?:[ \t]{0,40}@[^\n]{0,200}\n){0,5}"""
    r"""[ \t]{0,40}(?:async[ \t]{1,4})?def[ \t]{1,4}(?P<pyname>\w{1,80})"""
)


__all__ = ["AgentChainDetector"]
