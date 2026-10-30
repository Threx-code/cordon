"""The agent-chain findings in the settings files agents and editors load.

`.claude/settings*.json` hooks, helpers, the status line, wildcard permissions and bypass modes, and
where it sends the agent's traffic; VS Code's auto-approve; Codex's approval and sandbox modes and
where model requests go; a plugin marketplace installing over plain HTTP; a command, subagent or
skill that pre-approves any shell command; and the commands an editor runs on opening a folder."""

from __future__ import annotations

import re
import tomllib
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents import configuration
from cordon_scanner.detect.agents.autorun import Autorun
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.detect.agents.text_findings import AgentTextFindings
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.models import (
    Finding,
    Severity,
)
from cordon_scanner.intel.registry import ATR_TEXT_KINDS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import ScanContext


class SettingsFileFindings:
    """The agent-chain findings in agent and editor settings files."""

    @classmethod
    def agent_settings(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
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
                    ATR_TEXT_KINDS,
                    within=text,
                    local=not configuration.CommandClassifier.reaches_out(command),
                )
            attack = next(
                (
                    (c, v)
                    for c in commands
                    if (v := configuration.CommandClassifier.classify(c)) is not None
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
                    if not configuration.CommandClassifier.is_routine(c)
                    and configuration.CommandClassifier.reaches_out(c)
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
        yield from cls._settings_commands(unit, ctx, settings, text)
        yield from cls._settings_reach(unit, ctx, settings, text)
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            allowed = [str(a) for a in permissions.get("allow") or () if isinstance(a, str)]
            wildcard = next(
                (
                    a
                    for a in allowed
                    if re.fullmatch(
                        r"\s*(?:\*|Bash|Bash\(\s*(?:\*\s*)?\)|Bash\(\s*\*\s*:\s*\*\s*\))\s*", a
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

    @classmethod
    def _settings_commands(
        cls, unit: FileUnit, ctx: ScanContext, settings: dict[str, Any], text: str
    ) -> Iterator[Finding]:
        """Commands a settings file has the agent run without a hook: helpers and the status line."""
        commands = [(key, settings.get(key)) for key in cls._HELPER_KEYS]
        status = settings.get("statusLine")
        if isinstance(status, dict):
            commands.append(("statusLine", status.get("command")))
        for key, command in commands:
            if not isinstance(command, str):
                continue
            verdict = configuration.CommandClassifier.classify(command)
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

    @classmethod
    def _settings_reach(
        cls, unit: FileUnit, ctx: ScanContext, settings: dict[str, Any], text: str
    ) -> Iterator[Finding]:
        """Where a settings file sends the agent's traffic, and what it lets the agent reach."""
        env = settings.get("env")
        if isinstance(env, dict):
            for name, value in env.items():
                if configuration.ApiTraffic.redirects_api(str(name), value):
                    yield AgentFinding.at_text(
                        "SUSPECT.AGENT.API_REDIRECT.001",
                        unit,
                        ctx,
                        text,
                        str(value),
                        message=RULES["SUSPECT.AGENT.API_REDIRECT.001"].message
                        + f" ({name} -> {configuration.ApiTraffic.host_of(str(value))})",
                    )
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            wide = next(
                (
                    d
                    for d in permissions.get("additionalDirectories") or ()
                    if configuration.ServerExposure.wide_directory(d)
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

    @classmethod
    def vscode_settings(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = McpConfigs._json(unit.content)
        if isinstance(settings, dict) and settings.get("chat.tools.autoApprove") is True:
            yield AgentFinding.at_text(
                "POLICY.AGENT.AUTO_APPROVE.001",
                unit,
                ctx,
                unit.content.text,
                "chat.tools.autoApprove",
            )

    @classmethod
    def autorun(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """Commands an editor or agent runs when the folder is opened or the environment built.

        The handling lives in `autorun.py` so the rule can grow without this file; this delegates."""
        yield from Autorun.autorun_findings(unit, ctx)

    @classmethod
    def codex_config(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
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
            if isinstance(base, str) and configuration.ApiTraffic.redirects_api(
                "OPENAI_BASE_URL", base
            ):
                yield AgentFinding.at_text(
                    "SUSPECT.AGENT.API_REDIRECT.001",
                    unit,
                    ctx,
                    text,
                    base,
                    message=RULES["SUSPECT.AGENT.API_REDIRECT.001"].message
                    + f" (model provider -> {configuration.ApiTraffic.host_of(base)})",
                )

    @classmethod
    def marketplace(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
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

    @classmethod
    def command_permissions(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """A slash command, subagent or skill that pre-approves any shell command."""
        head = unit.content.text[:4000]
        if not head.startswith("---"):
            return
        found = cls._ANY_BASH.search(head.split("\n---", 1)[0])
        if found is not None:
            yield AgentFinding.at_text(
                "POLICY.AGENT.WILDCARD_PERMISSION.001", unit, ctx, unit.content.text, found.group(0)
            )


__all__ = ["SettingsFileFindings"]
