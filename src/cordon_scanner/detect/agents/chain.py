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
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents import agent_config
from cordon_scanner.detect.agents.agent_semantics import AgentSemantics
from cordon_scanner.detect.agents.autorun import AUTORUN_PATHS
from cordon_scanner.detect.agents.mcp_servers.description_model import (
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

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import ScanContext, Unit
from cordon_scanner.detect.agents.extension_files import ExtensionFileFindings
from cordon_scanner.detect.agents.extensions import ExtensionNames
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.instruction_files import InstructionFileFindings
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
from cordon_scanner.detect.agents.settings_files import SettingsFileFindings
from cordon_scanner.detect.agents.skills import SkillScripts
from cordon_scanner.detect.agents.text_findings import AgentTextFindings
from cordon_scanner.detect.agents.text_patterns import (
    FETCH_EXEC,
    ORDERS_A_COMMAND,
)

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
            findings.extend(InstructionFileFindings.instructions(unit, ctx))
        if AgentPaths._paths_match(path, AGENT_SETTINGS_PATHS):
            findings.extend(SettingsFileFindings.agent_settings(unit, ctx))
        if AgentPaths._paths_match(path, VSCODE_SETTINGS_PATHS):
            findings.extend(SettingsFileFindings.vscode_settings(unit, ctx))
        if AgentPaths._paths_match(path, MCP_PATHS):
            findings.extend(self._mcp(unit, ctx))
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
            findings.extend(self._server_source(unit, ctx))
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

    # -- A2 ------------------------------------------------------------------------------

    """Claude Code settings whose value is a shell command the agent runs itself."""

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
