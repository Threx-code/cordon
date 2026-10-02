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

import contextlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.core import references as ref
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.core.walker import PathGlob
from cordon_scanner.detect import agent_config
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import SourcePaths
from cordon_scanner.intel import atr
from cordon_scanner.intel.installers import KNOWN_INSTALLERS, OfficialInstallers

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import ScanContext, Unit

INSTRUCTION_PATHS: Final = (
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/AGENT.md",
    "**/GEMINI.md",
    "**/.cursorrules",
    "**/.cursor/rules/**",
    "**/.windsurfrules",
    "**/.windsurf/rules/**",
    "**/.clinerules",
    "**/.clinerules/**",
    "**/.github/copilot-instructions.md",
    "**/.github/instructions/**",
    "**/.github/prompts/**",
    "**/SKILL.md",
    "**/.claude/commands/**",
    "**/.claude/agents/**",
    "**/.claude/skills/**",
    "**/.claude/output-styles/**",
    # Copilot's custom chat modes, agents and the rest of its prompt files.
    "**/.github/chatmodes/**",
    "**/.github/agents/**",
    # Cursor, Gemini CLI, opencode and Windsurf commands and workflows: prompts the agent runs.
    "**/.cursor/commands/**",
    "**/.gemini/commands/**",
    "**/.opencode/agent/**",
    "**/.opencode/command/**",
    "**/.windsurf/workflows/**",
    # Kiro, Amazon Q, JetBrains Junie, Augment, Trae, Roo, Continue, Zed and goose.
    "**/.kiro/steering/**",
    "**/.amazonq/rules/**",
    "**/.junie/**",
    "**/.augment-guidelines",
    "**/.augment/rules/**",
    "**/.trae/rules/**",
    "**/.roo/rules/**",
    "**/.roo/rules-*/**",
    "**/.continue/rules/**",
    "**/.continue/prompts/**",
    "**/.rules",
    "**/.goosehints",
)
AGENT_SETTINGS_PATHS: Final = (
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    "**/managed-settings.json",
    # Hooks in the other agents that run them, in the same `{"hooks": {event: [...]}}` shape:
    # a Claude Code plugin's `hooks/hooks.json`, Cursor's and Windsurf's `hooks.json`, Gemini
    # CLI's settings, Kiro's hook files.
    "**/hooks/hooks.json",
    "**/.cursor/hooks.json",
    "**/.windsurf/hooks.json",
    "**/.gemini/settings.json",
    "**/.kiro/hooks/*",
)
VSCODE_SETTINGS_PATHS: Final = ("**/.vscode/settings.json",)
MCP_PATHS: Final = (
    "**/.mcp.json",
    "**/.cursor/mcp.json",
    "**/.vscode/mcp.json",
    "**/.gemini/settings.json",
    "**/.windsurf/mcp.json",
    "**/.roo/mcp.json",
    "**/claude_desktop_config.json",
    "**/mcp.json",
    "**/cline_mcp_settings.json",
    "**/.zed/settings.json",
    "**/opencode.json",
    "**/opencode.jsonc",
    "**/.codex/config.toml",
    "**/.continue/config.yaml",
    "**/.continue/mcpServers/*",
)
WORKFLOW_PATHS: Final = ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml")
AUTORUN_PATHS: Final = (
    "**/.vscode/tasks.json",
    "**/.devcontainer/devcontainer.json",
    "**/.devcontainer.json",
    "**/.devcontainer/*/devcontainer.json",
    "**/.cursor/environment.json",
)
"""Files whose commands an editor or agent runs without anyone typing them: VS Code tasks set to
run when the folder opens, dev-container lifecycle commands (`initializeCommand` on the host
itself), and the install and start steps of Cursor's background-agent environment."""
CODEX_CONFIG_PATHS: Final = ("**/.codex/config.toml",)
MARKETPLACE_PATHS: Final = ("**/.claude-plugin/marketplace.json",)
COMMAND_PATHS: Final = (
    "**/.claude/commands/**",
    "**/.claude/agents/**",
    "**/.claude/skills/**/SKILL.md",
)

# -- A1: hidden characters -----------------------------------------------------------------
#
# As UTF-8 byte sequences, so no decoding surprise applies.
_BIDI: Final = rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]"
_ZERO_WIDTH: Final = rb"\xe2\x80[\x8b\x8c]|\xe2\x81\xa0|(?<=[^\s\"'`])\xef\xbb\xbf"
"""Zero-width space and non-joiner, word joiner, and a BOM inside text. The zero-width JOINER is
left out: it is part of every compound emoji."""
_TAG: Final = rb"\xf3\xa0[\x80\x81][\x80-\xbf]"
"""Unicode Tag characters, U+E0000 to U+E007F. Each mirrors an ASCII character and renders as
nothing, so a whole sentence can sit invisibly in a line. The one legitimate use is a
subdivision flag emoji, which follows U+1F3F4 and is excluded below."""
_VARIATION: Final = rb"\xef\xb8[\x80-\x8d]|\xf3\xa0(?:\x84[\x80-\xbf]|\x85[\x80-\xbf]|\x86[\x80-\xbf]|\x87[\x80-\xaf])"
"""Variation selectors 1 to 14 and the supplementary 17 to 256. VS15 and VS16 (text or emoji
presentation) are ordinary and excluded; the rest can encode a byte each, invisibly."""
HIDDEN: Final = re.compile(b"|".join((_BIDI, _ZERO_WIDTH, _TAG, _VARIATION)))
_FLAG_TAGS: Final = re.compile(rb"\xf0\x9f\x8f\xb4(?:\xf3\xa0[\x80\x81][\x80-\xbf]){1,16}")

_INJECTION: Final = re.compile(
    r"(?i)\b(?:ignore|disregard|forget)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b"
    r"[^\n]{0,20}\b(?:instructions?|rules|guidelines|directions|prompts?)\b"
    # "These rules override any conflicting instructions" sets precedence inside the file;
    # overriding the agent's own earlier or system instructions is the attack.
    r"|\boverride\b[^\n]{0,40}\b(?:previous|prior|above|earlier|your|system)\b"
    r"[^\n]{0,20}\b(?:instructions?|rules|guidelines|directions|prompts?)\b"
    # Set everything earlier aside: "disregard everything you were told", "pay no attention to
    # the system prompt".
    r"|\b(?:ignore|disregard|forget|discard|set\s+aside|pay\s+no\s+attention\s+to)\b[^\n.]{0,30}"
    r"\b(?:everything|anything|all)\b[^\n.]{0,20}\b(?:you\s+(?:were|have\s+been|'ve\s+been)\s+(?:told|given|asked)|before|so\s+far)\b"
    r"|\b(?:ignore|disregard|forget|discard|set\s+aside|pay\s+no\s+attention\s+to)\b[^\n.]{0,20}"
    r"\b(?:the|your)\s+(?:system\s+(?:prompt|message|instructions?)|original\s+(?:prompt|instructions?))\b"
    # Replace them: "new instructions supersede all prior ones".
    r"|\b(?:supersedes?|replaces?|overrides?|takes?\s+precedence\s+over|voids?|nullif(?:y|ies)|cancels?)\b"
    r"[^\n.]{0,20}\b(?:all\s+)?(?:prior|previous|earlier|original|system)\b[^\n.]{0,15}\b(?:ones|instructions?|prompts?|rules|directives|guidance)\b"
    r"|\byou\s+are\s+(?:now\s+)?(?:unrestricted|unfiltered|no\s+longer\s+bound|free\s+of\s+(?:all\s+)?(?:rules|restrictions))\b"
    # Hide it: "keep this step from the user", "never mention it in a summary".
    r"|\b(?:keep|hide|conceal|withhold)\b[^\n.]{0,40}\bfrom\s+(?:the\s+)?(?:user|human|developer|reviewer|operator|maintainer)s?\b"
    r"|\b(?:do not|don't|never)\s+(?:mention|report|reveal|disclose|show)\s+(?:it|this|that|these|them)\b[^\n.]{0,30}"
    r"\b(?:summary|summaries|response|reply|output|report|commit\s+message|user)\b"
    r"|\b(?:do not|don't|never)\s+(?:tell|inform|mention|show|reveal)[^\n]{0,20}\b(?:the\s+)?user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying)\s+(?:the\s+)?user\b"
    r"|\byou are now\b[^\n]{0,40}\b(?:mode|unrestricted|jailbroken|DAN)\b"
)
_INJECTION_INTL: Final = re.compile(
    # The same two claims in the languages agent files are most often written in: "ignore the
    # previous instructions" and "do not tell the user". Wording is weak evidence in any language,
    # so this warns at the same grade the English pattern does.
    r"(?i)\bignora(?:r)?\s(?:todas\s)?las\sinstrucciones\s(?:anteriores|previas)"
    r"|\bno\s(?:le\s)?(?:digas|informes|menciones)\s(?:nada\s)?al\susuario"
    r"|\bignore[rz]?\s(?:toutes\s)?les\sinstructions\s(?:pr[ée]c[ée]dentes|ci-dessus)"
    r"|\bsans\s(?:le\s)?(?:dire|signaler|demander)\s[àa]\sl'utilisateur"
    r"|\bignorier(?:e|en)?\s(?:alle\s)?(?:vorherigen|bisherigen|obigen)\s(?:Anweisungen|Instruktionen)"
    r"|\bohne\sden\s(?:Benutzer|Nutzer)\szu\s(?:fragen|informieren|benachrichtigen)"
    r"|\bignor[ea]\s(?:todas\s)?as\sinstru[çc][õo]es\santeriores"
    r"|\bsem\s(?:avisar|informar|perguntar)\s(?:ao|o)\susu[áa]rio"
    r"|\bignora\s(?:tutte\s)?le\sistruzioni\sprecedenti"
    r"|\bnegeer\s(?:alle\s)?(?:vorige|eerdere)\sinstructies"
    r"|игнорируй\s(?:все\s)?(?:предыдущие\s)?инструкции"
    r"|не\s(?:говори|сообщай)\sпользователю"  # noqa: RUF001  (Russian, on purpose)
    r"|忽略(?:之前|以上|先前|所有)的?(?:指令|说明|指示)"
    r"|不要(?:告诉|通知)用户"
    r"|(?:以前|これまで|上記)の指示を無視"
    r"|ユーザーに(?:言わ|伝え|知らせ)ないで"
    r"|이전\s?지시(?:를|사항을)?\s?무시"
    r"|사용자에게\s?알리지\s?마"
)
_FETCH_EXEC: Final = re.compile(
    r"(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,300}\|\s*(?:iex|invoke-expression)\b"
    r"|\b(?:iex|invoke-expression)\s*[\(\s]\s*[\(\s]*new-object\s+net\.webclient\b"
    # Something to fetch -- a URL, a host or a variable -- before the pipe: "no `curl | bash`
    # flows" names the shape without doing it.
    r"|\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,300}?(?:https?://|\$\{?\w|\b[\w-]+\.[a-z]{2,}\b)"
    r"[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:curl|wget)\b[^\n]{0,300}(?:\|\s*python3?\b(?![ \t]{1,8}-[cm]\b)|>\s*/tmp/[^\s]+\s*&&\s*(?:ba)?sh\b)"
    r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b"
)
_URL_HOST: Final = re.compile(r"(?i)https?://([a-z0-9.-]{1,253})(/[^\s|\"'`)]{0,200})?")
_SHORTENERS: Final = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "shorturl.at", "goo.gl"}
)
_RAW_IP_URL: Final = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_DECODED: Final = re.compile(r"(?i)\bbase64\s+(?:-d|--decode)\b")
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


class InstructionText:
    "Reading an agent instruction file: fetches, quotation, prohibitions, hidden characters."

    @staticmethod
    def _alarming_fetch(command: str) -> bool:
        """A fetch-and-run whose destination or shape has no business in setup instructions."""
        from cordon_scanner.intel.hosts import Destinations

        raw = command.encode("utf-8", "replace")
        if (
            _DECODED.search(command)
            or _RAW_IP_URL.search(command)
            or Destinations.destination_matcher().search(raw)
        ):
            return True
        found = _URL_HOST.search(command)
        host = found.group(1).lower() if found else ""
        # `astral.sh.evil.example` is built to read as the official host it is not.
        lookalike = any(host.startswith(f"{known}.") for known, _ in KNOWN_INSTALLERS)
        return host in _SHORTENERS or lookalike

    @staticmethod
    def _quoted(text: str, match: re.Match[str]) -> bool:
        """Whether a phrase is quoted rather than said: "papers discuss 'ignore previous
        instructions' attacks" mentions the words; the injection uses them."""
        before = text[: match.start()].rstrip(" ")
        if not before:
            return False
        close = _QUOTES.get(before[-1])
        if close is None:
            return False
        return text[match.end() : match.end() + 3].lstrip(" ").startswith(close)

    @staticmethod
    def _forbidden(text: str, match: re.Match[str]) -> bool:
        """Whether "without asking the user" sits under a prohibition in its own sentence: "never
        install packages without asking the user" tells the agent to ask; "push without asking the
        user" tells it not to."""
        if not match.group(0).lower().startswith("without"):
            return False
        start = max(text.rfind(c, 0, match.start()) for c in ".!?\n")
        return _PROHIBITION.search(text, start + 1, match.start()) is not None

    @staticmethod
    def _decode_tags(raw: bytes) -> str:
        """ASCII spelled by Unicode Tag characters outside flag emoji, as a reader would see it."""
        text = raw.decode("utf-8", errors="ignore")
        out = []
        previous_flag = False
        for character in text:
            code = ord(character)
            if 0xE0020 <= code <= 0xE007E and not previous_flag:
                out.append(chr(code - 0xE0000))
            previous_flag = code == 0x1F3F4 or (previous_flag and 0xE0000 <= code <= 0xE007F)
        return "".join(out).strip()

    @staticmethod
    def _triggers(text: str) -> list[str]:
        found: list[str] = []
        inline = re.search(r"(?m)^['\"]?on['\"]?\s*:\s*(\[[^\]]*\]|[\w-]+)\s*$", text)
        if inline:
            found += re.findall(r"[\w-]+", inline.group(1))
        block = re.search(r"(?m)^['\"]?on['\"]?\s*:\s*$([\s\S]*?)(?=^\S)", text + "\nend:")
        if block:
            found += re.findall(r"(?m)^\s{1,6}([\w-]+)\s*:", block.group(1))
            found += re.findall(r"(?m)^\s{1,6}-\s*([\w-]+)\s*$", block.group(1))
        return found

    @staticmethod
    def _byte_span(text: str, match: re.Match[str]) -> tuple[int, int]:
        start = len(text[: match.start()].encode("utf-8"))
        return start, start + len(match.group(0).encode("utf-8"))


_EXFIL_PATHS: Final = re.compile(
    r"(?i)(?:~|\$HOME)/\.(?:ssh|aws|npmrc|pypirc|docker/config\.json|kube/config)|\.env\b|id_rsa|\bGITHUB_TOKEN\b"
    r"|\boutput\s+of\s+`?(?:env|printenv|set)\b|\benvironment\s+variables\b"
)
_SEND: Final = re.compile(
    r"(?i)\b(?:send|post|upload|exfiltrate|forward|copy|transmit|paste)\b[^\n]{0,80}\b(?:to|into)\b"
    r"[^\n]{0,40}?(?:https?://|\b[a-z0-9-]{1,63}\.(?:com|net|org|io|dev|xyz|top|site|ru|cn|me)\b"
    r"|\bwebhook|\bendpoint|\bserver\b|\bgist\b|\bpastebin|\bdiscord|\btelegram|\bslack\b"
    r"|\bngrok|\bemail\b|[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}\.)"
)
"""An instruction to move something somewhere off the machine. The destination is what makes it
exfiltration: "copy `.env.template` to `.env`" is setup, and netdata's and AutoGPT's agent guides
say exactly that; "send `~/.ssh/id_rsa` to https://..." or "post the `.env` to this webhook" is
the attack."""

# -- A3: MCP launch commands -----------------------------------------------------------------
_RUNNERS: Final = {
    "npx": "npm",
    "bunx": "npm",
    "pnpx": "npm",
    "uvx": "pypi",
    "pipx": "pypi",
}
_DLX_RUNNERS: Final = {
    ("pnpm", "dlx"): "npm",
    ("yarn", "dlx"): "npm",
    ("pipx", "run"): "pypi",
    ("uv", "tool"): "pypi",
}
_PLACEHOLDER: Final = re.compile(
    r"^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$|^<[^>]+>$|^(?:your|changeme|xxx+|placeholder)", re.I
)
_SECRET_NAME: Final = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)"
)
# Hosts to recognise in a URL, not addresses to bind.
_LOCAL_HOSTS: Final = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"}  # noqa: S104
)

# -- A6: agent actions in CI -----------------------------------------------------------------
AGENT_ACTIONS: Final = {
    "anthropics/claude-code-action": "Claude Code",
    "anthropics/claude-code-base-action": "Claude Code",
    "google-github-actions/run-gemini-cli": "Gemini CLI",
    "openai/codex-action": "Codex",
}
FIXED_IN: Final = {"anthropics/claude-code-action": (1, 0, 94)}
"""Agent actions with a published fix, and the first version carrying it, as known when this build
was cut. `intel/data/agent-actions.json`, refreshed through the intel feed, extends and overrides it."""


class AgentRules:
    "The agent detector's rules, and the agent actions whose fixed versions are known."

    @staticmethod
    def agent_actions() -> dict[str, tuple[str, tuple[int, int, int] | None]]:
        """Action -> (agent name, first fixed version), from the intel file over the built-in table."""
        from cordon_scanner.intel import datafile

        known: dict[str, tuple[str, tuple[int, int, int] | None]] = {
            action: (agent, FIXED_IN.get(action)) for action, agent in AGENT_ACTIONS.items()
        }
        for action, entry in (
            datafile.IntelDataFile.newest("agent-actions.json").get("actions") or {}
        ).items():
            if isinstance(entry, dict):
                fixed = ExtensionNames._semver(str(entry.get("fixed") or ""))
                known[str(action).lower()] = (
                    str(entry.get("agent") or action),
                    fixed or known.get(str(action).lower(), ("", None))[1],
                )
        return known

    @staticmethod
    def _rule(*args: Any, **kwargs: Any) -> AgentRule:
        return AgentRule(*args, **kwargs)

    @staticmethod
    def atr_rule_id(category: str) -> str:
        suffix, _ = ATR_CATEGORIES.get(category, ATR_CATEGORIES["prompt-injection"])
        return f"SUSPECT.AGENT.ATR.{suffix}.001"


EXTENSION_PATHS: Final = (
    "**/.vscode/extensions.json",
    "**/.devcontainer.json",
    "**/.devcontainer/devcontainer.json",
    "**/.devcontainer/*/devcontainer.json",
)
VSIX_MANIFEST: Final = "extension/package.json"
"""The manifest inside a `.vsix`, read when the archive is expanded."""
_EXTENSION_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$")
_MALWARE_REASONS: Final = ("malware", "potentially malicious")
_SUSPECT_REASONS: Final = ("impersonation", "untrustworthy", "typosquat")
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


@dataclass(frozen=True)
class AgentRule:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    references: tuple[str, ...] = ()


RULES: Final = {
    rule.rule_id: rule
    for rule in (
        AgentRules._rule(
            "SUSPECT.AGENT.HIDDEN_TEXT.001",
            "Hidden characters in an agent instruction file",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This agent instruction file contains characters that render as nothing: zero-width, "
            "bidirectional, Unicode Tag or variation-selector characters. A coding agent reads "
            "them; the person reviewing the file does not. That is how a rules-file backdoor "
            "hides an instruction.",
            "Remove the characters. If a character is needed, write it as a visible escape.",
            (ref.TROJAN_SOURCE, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.INJECTION_TEXT.001",
            "Instruction-like text aimed at a coding agent",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.LOW,
            "This agent instruction file tells the agent to set aside its instructions or to act "
            "without telling the user. Wording alone is not proof of an attack, so this is "
            "reported below the default gate; read the passage.",
            "Remove or reword the passage. Agent instructions should never ask for secrecy from "
            "the user.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.FETCH_EXEC.001",
            "Agent instructions that fetch and execute remote code",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This agent instruction file tells the agent to download something and run it. An "
            "agent that follows it executes whatever the remote host serves, with the "
            "developer's rights.",
            "Pin what is installed and verify it, or remove the instruction.",
            (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.CREDENTIAL_EXFIL.001",
            "Agent instructions that move credentials somewhere",
            Category.MALICIOUS,
            Severity.CRITICAL,
            Confidence.MEDIUM,
            "This agent instruction file tells the agent to send or copy a credential store "
            "(SSH keys, cloud credentials, .env, a token) somewhere. An instruction to move "
            "credentials is what an attacker plants in a rules file; read the passage.",
            "Treat the repository as compromised until the passage is explained.",
            (ref.EXPOSED_RESOURCE, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.HOOK.001",
            "An agent hook committed to the repository",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.HIGH,
            "This agent settings file defines hooks, shell commands the agent runs on events such "
            "as every tool call. Committed to a repository, they run on the machine of whoever "
            "opens it with the agent.",
            "Keep hooks in user-level settings, or review each command as you would a "
            "postinstall script.",
            (ref.CLAUDE_CODE_HOOKS,),
        ),
        AgentRules._rule(
            "MALWARE.AGENT.HOOK_FETCH_EXEC.001",
            "An agent hook that fetches and executes remote code",
            Category.MALICIOUS,
            Severity.CRITICAL,
            Confidence.HIGH,
            "An agent hook committed to this repository downloads and runs code. It executes on "
            "the machine of whoever opens the repository with the agent, before they have "
            "reviewed anything.",
            "Remove the hook, and treat the repository as untrusted.",
            (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.CLAUDE_CODE_HOOKS),
        ),
        AgentRules._rule(
            "POLICY.AGENT.WILDCARD_PERMISSION.001",
            "Agent permissions allow any shell command",
            Category.POLICY,
            Severity.MEDIUM,
            Confidence.HIGH,
            "These committed agent settings pre-approve any shell command, so the agent runs "
            "whatever a prompt-injected instruction asks without a confirmation.",
            "Allow specific commands (for example `Bash(npm test)`) instead of a wildcard.",
            (ref.EXECUTION_WITH_UNNECESSARY_PRIVILEGE, ref.CLAUDE_CODE_SETTINGS),
        ),
        AgentRules._rule(
            "POLICY.AGENT.AUTO_APPROVE.001",
            "Agent confirmations switched off in committed settings",
            Category.POLICY,
            Severity.HIGH,
            Confidence.HIGH,
            "These committed settings switch off the agent's confirmations (a bypass or "
            "auto-approve mode, or every MCP server in the project enabled unasked). Whoever "
            "opens the repository inherits it.",
            "Remove the setting from the repository; each developer decides it for themselves.",
            (ref.INSECURE_DEFAULT, ref.CLAUDE_CODE_SETTINGS),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.UNPINNED.001",
            "An MCP server launched from an unpinned package",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.HIGH,
            "This MCP server is started by downloading a package at whatever version the registry "
            "serves today. A compromised release runs on the next launch, with the developer's "
            "rights.",
            "Pin the exact version (`pkg@1.2.3`), or a container image by digest.",
            (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.MCP_SECURITY),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.INSECURE_TRANSPORT.001",
            "A remote MCP server over plain HTTP",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This MCP server is reached over unencrypted HTTP. Anyone on the path can read the "
            "tool traffic and inject tool responses the agent will act on.",
            "Use https.",
            (ref.CLEARTEXT_TRANSMISSION, ref.MCP_SECURITY),
        ),
        AgentRules._rule(
            "SECRET.MCP.INLINE_CREDENTIAL.001",
            "A credential written inline in an MCP configuration",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This MCP configuration carries a credential as a literal value. Committed, it is "
            "readable by everyone with access to the repository and its history.",
            "Reference an environment variable (`${API_KEY}`) and rotate the exposed value.",
            (ref.HARDCODED_CREDENTIALS,),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.SHELL_LAUNCH.001",
            "An MCP server launched through a shell that fetches code",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This MCP server's launch command downloads and executes code through a shell, so "
            "what runs is whatever the remote host serves.",
            "Launch a pinned package or image directly.",
            (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.MCP_SECURITY),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.CI_UNTRUSTED_TRIGGER.001",
            "An AI agent in CI reads text an outsider can write",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This workflow runs an AI coding agent on an event anyone can raise (an issue, a "
            "comment, a pull request) with secrets or a write token in scope and no check on who "
            "raised it. Instructions hidden in that text reach the agent, which can then use "
            "the token or leak the secret: the 'Comment and Control' attack.",
            "Gate the job on `author_association` (OWNER, MEMBER, COLLABORATOR), give the job "
            "read-only permissions, and restrict the agent's tools.",
            (ref.GITHUB_ACTIONS_HARDENING, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.CI_PROMPT_INJECTION.001",
            "Untrusted event text passed straight into an agent's prompt",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This workflow interpolates text from an issue, comment or pull request directly "
            "into an AI agent's prompt. The author of that text writes part of the agent's "
            "instructions.",
            "Let the action read the event itself, and keep untrusted text out of the prompt "
            "template.",
            (ref.UNTRUSTED_INPUT_IN_BUILD, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "VULNERABLE.AGENT.ACTION_VERSION.001",
            "An AI agent action below its security fix",
            Category.VULNERABLE,
            Severity.HIGH,
            Confidence.HIGH,
            "This workflow pins an AI agent action to a version older than its published security "
            "fix.",
            "Upgrade the action, and pin the upgraded release by commit SHA.",
            (ref.GITHUB_ACTIONS_HARDENING,),
        ),
        AgentRules._rule(
            "MALWARE.EXTENSION.REMOVED.001",
            "A recommended or vendored editor extension was removed from the Marketplace as malware",
            Category.MALICIOUS,
            Severity.CRITICAL,
            Confidence.HIGH,
            "This repository recommends, or ships the package of, an editor extension Microsoft removed "
            "from the Visual Studio Marketplace as malware. Opening the repository in VS Code prompts "
            "every developer to install it.",
            "Remove the extension from the recommendations and delete any vendored .vsix. Check the "
            "machines that installed it.",
            (ref.VSCODE_REMOVED_EXTENSIONS,),
        ),
        AgentRules._rule(
            "SUSPECT.EXTENSION.REMOVED.001",
            "A recommended or vendored editor extension was removed from the Marketplace",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This repository recommends, or ships the package of, an editor extension Microsoft removed "
            "from the Visual Studio Marketplace for impersonation or as untrustworthy.",
            "Replace it with the extension it imitates, or remove it.",
            (ref.VSCODE_REMOVED_EXTENSIONS,),
        ),
        AgentRules._rule(
            "SUSPECT.EXTENSION.LOOKALIKE.001",
            "A recommended editor extension imitates a popular one",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "This repository recommends an editor extension whose identifier differs from a widely "
            "installed one by one character, or by publisher alone.",
            "Check the publisher. Recommend the extension from its real publisher instead.",
            (ref.VSCODE_REMOVED_EXTENSIONS,),
        ),
        AgentRules._rule(
            "OPERATIONAL.MCP.UNRESOLVED",
            "An MCP server package was not examined",
            Category.OPERATIONAL,
            Severity.INFO,
            Confidence.HIGH,
            "This MCP server runs a package whose code was not read: it is not installed in the "
            "scanned tree, and fetching it needs --online (fetched, never installed, never run).",
            "Scan with --online, or vendor the package so the scan can read it.",
            (ref.MCP_SECURITY,),
        ),
    )
}

RULES.update(
    {
        rule.rule_id: rule
        for rule in (
            AgentRules._rule(
                "MALWARE.AGENT.HOOK_EXFIL.001",
                "An agent hook that sends credentials away or opens a remote shell",
                Category.MALICIOUS,
                Severity.CRITICAL,
                Confidence.HIGH,
                "An agent hook committed to this repository sends credentials or the environment "
                "to another machine, or opens a shell to one. It runs on the machine of whoever "
                "opens the repository with the agent.",
                "Remove the hook, rotate any credential the machine holds, and treat the "
                "repository as untrusted.",
                (ref.CLAUDE_CODE_HOOKS, ref.EXPOSED_RESOURCE),
            ),
            AgentRules._rule(
                "MALWARE.AGENT.AUTORUN.001",
                "A command an editor or agent runs on its own attacks the machine",
                Category.MALICIOUS,
                Severity.CRITICAL,
                Confidence.HIGH,
                "A command this repository configures to run without anyone typing it -- a "
                "settings helper the agent calls, a task that starts when the folder opens, a "
                "dev-container lifecycle command, an agent environment's install step -- downloads "
                "and runs code, sends credentials away, or opens a remote shell.",
                "Remove the command and treat the repository as untrusted.",
                (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.CLAUDE_CODE_SETTINGS),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.API_REDIRECT.001",
                "Agent API traffic redirected to a host that is not the provider",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.HIGH,
                "These committed settings point the agent's API base URL or proxy at a host that "
                "is not the model provider. Every request -- and the API key with it -- goes "
                "there instead, the shape of CVE-2026-21852. An organisation's own gateway looks "
                "the same; allow it explicitly if that is what this is.",
                "Remove the variable from committed settings; set a gateway per developer.",
                (ref.CLAUDE_CODE_SETTINGS, ref.EXPOSED_RESOURCE),
            ),
            AgentRules._rule(
                "POLICY.AGENT.WIDE_DIRECTORY.001",
                "Agent given the whole disk or home directory to work in",
                Category.POLICY,
                Severity.MEDIUM,
                Confidence.HIGH,
                "These committed settings add the root or home directory to the agent's working "
                "directories, so every file there -- SSH keys, cloud credentials -- is in reach "
                "of anything that steers the agent.",
                "Add the specific directories the work needs.",
                (ref.EXECUTION_WITH_UNNECESSARY_PRIVILEGE, ref.CLAUDE_CODE_SETTINGS),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.PLUGIN_SOURCE.001",
                "Agent plugins installed from an unverified source",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A plugin marketplace this repository declares installs plugins over plain HTTP, "
                "or the repository's settings enable plugins from a marketplace it adds itself, "
                "so opening it with the agent installs code nobody reviewed.",
                "Install plugins from a marketplace each developer chose, over https.",
                (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.CLAUDE_CODE_SETTINGS),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.CONTAINER_HOST_ACCESS.001",
                "An MCP server's container is given the host",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.HIGH,
                "This MCP server runs in a container launched with privilege, the host's "
                "namespaces, its Docker socket, its root or home directory, or its credential "
                "directories -- whatever the server does, it does to the host.",
                "Mount only the directories the server needs, read-only where it can, and drop "
                "--privileged and host namespaces.",
                (ref.EXECUTION_WITH_UNNECESSARY_PRIVILEGE, ref.MCP_SECURITY),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.ENV_INJECTION.001",
                "An MCP server's environment loads code into it before it starts",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.HIGH,
                "This MCP server is launched with an environment variable that loads code into "
                "the process -- LD_PRELOAD, DYLD_INSERT_LIBRARIES, BASH_ENV, NODE_OPTIONS "
                "--require and their kin -- so whatever that names runs inside the server, "
                "whatever the server's own package is.",
                "Remove the variable.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.UNTRUSTED_REMOTE.001",
                "A remote MCP server on a tunnel, paste or interaction host",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "This remote MCP server is reached through a host whose business is temporary "
                "tunnels, pastes or capturing requests -- somewhere a published service does not "
                "live -- or a bare IP address.",
                "Connect to the vendor's own host.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.LOOKALIKE.001",
                "An MCP server package named like a popular one",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "This MCP server is launched from a package whose name is one or two characters "
                "from a widely used server's, or under a scope one character from its scope.",
                "Check the name against the server's documentation and launch the real package.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "POLICY.AGENT.MCP_BROAD_SCOPE.001",
                "A filesystem MCP server given the whole disk or home directory",
                Category.POLICY,
                Severity.MEDIUM,
                Confidence.HIGH,
                "This filesystem MCP server is given the root or home directory, so it can read "
                "and write SSH keys, cloud credentials and every other repository on the machine.",
                "Pass the project directory instead.",
                (ref.EXECUTION_WITH_UNNECESSARY_PRIVILEGE, ref.MCP_SECURITY),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                "A tool in this repository's MCP server instructs the agent",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool description in this repository's own MCP server addresses the agent "
                "instead of describing the tool. Agents read every description as context, so "
                "this steers the agent whenever the server is connected -- tool poisoning, or "
                "shadowing when it reaches for other tools.",
                "Rewrite the description to say only what the tool does.",
                (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.SENSITIVE_IMPORT.001",
                "An agent instruction file imports a credential file",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.HIGH,
                "This instruction file imports a credential file into the agent's context with "
                "an `@path` reference. The agent reads it on every session and sends it to the "
                "model provider with the rest of the context.",
                "Remove the import.",
                (ref.EXPOSED_RESOURCE, ref.OWASP_LLM_PROMPT_INJECTION),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001",
                "An agent instruction file tells the agent to fetch and follow remote text",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "This instruction file tells the agent to fetch text from a URL and follow it, so "
                "whoever controls that URL writes the agent's instructions, and can change them "
                "after this file was reviewed.",
                "Commit the instructions instead of linking them.",
                (ref.OWASP_LLM_PROMPT_INJECTION,),
            ),
        )
    }
)


ATR_CATEGORIES: Final = {
    "prompt-injection": ("PROMPT_INJECTION", "Text that tries to override an agent's instructions"),
    "tool-poisoning": (
        "TOOL_POISONING",
        "Text that turns a tool into a channel for steering the agent",
    ),
    "context-exfiltration": (
        "CONTEXT_EXFILTRATION",
        "Text that asks an agent to move secrets or context off the machine",
    ),
    "agent-manipulation": (
        "AGENT_MANIPULATION",
        "Text that impersonates an agent or hijacks the agent's task",
    ),
    "privilege-escalation": (
        "PRIVILEGE_ESCALATION",
        "Text that asks an agent to widen its own permissions",
    ),
    "excessive-autonomy": (
        "EXCESSIVE_AUTONOMY",
        "Text that asks an agent to act without the user's confirmation",
    ),
    "skill-compromise": ("SKILL_COMPROMISE", "A skill or plugin shaped like a known compromise"),
    "data-poisoning": ("DATA_POISONING", "Text that plants triggers or false facts for an agent"),
    "model-abuse": ("MODEL_ABUSE", "Text that turns an agent toward abuse of the model"),
    "model-security": ("MODEL_SECURITY", "Text that targets the model's weights or safety"),
}
"""ATR's categories, each one Cordon rule; the finding names the ATR rules that matched."""


RULES.update(
    {
        AgentRules.atr_rule_id(category): AgentRules._rule(
            AgentRules.atr_rule_id(category),
            title,
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.LOW,
            "Text an agent reads from this repository matches the Agent Threat Rules catalogue: "
            f"{title[0].lower()}{title[1:]}. Wording is weak evidence alone, so this is reported "
            "below the default gate unless the matching rule is one ATR marks stable; read the "
            "passage.",
            "Remove the passage, or confirm it was written by someone the repository trusts. "
            "Agents act on what they read.",
            (ref.AGENT_THREAT_RULES, ref.OWASP_LLM_PROMPT_INJECTION),
        )
        for category, (_, title) in ATR_CATEGORIES.items()
    }
)


class AgentPaths:
    "Whether a path is one of the places an agent reads configuration from."

    @staticmethod
    def _paths_match(path: str, patterns: tuple[str, ...]) -> bool:
        return any(PathGlob.matches(path, pattern) for pattern in patterns)


class AgentChainDetector(BaseDetector):
    """Agent instruction files, agent settings, MCP configurations and AI agents in CI."""

    id = "agents"
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
            findings.extend(self._extension_recommendations(unit, ctx))
        if path == VSIX_MANIFEST and ".vsix!" in unit.content.path.lower():
            findings.extend(self._vsix_manifest(unit, ctx))
        if path.endswith(_SERVER_SOURCE_SUFFIXES) and _MCP_SDK.search(unit.content.text):
            findings.extend(self._server_source(unit, ctx))
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
            reason = McpServerSource._poisoned_description(description)
            if reason is not None:
                yield self._at_text(
                    "SUSPECT.MCP.TOOL_DESCRIPTION.001",
                    unit,
                    ctx,
                    text,
                    description[:80],
                    message=RULES["SUSPECT.MCP.TOOL_DESCRIPTION.001"].message + f" It {reason}.",
                )
            yield from self._threat_rules(unit, ctx, description, atr.TEXT_KINDS, within=text)
        names = (m.group("name") or m.group("pyname") for m in _TOOL_NAME.finditer(text))
        for name in dict.fromkeys(names):
            yield from self._threat_rules(unit, ctx, name, ("tool_name",), within=text)

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
        hidden = [
            m
            for m in HIDDEN.finditer(raw)
            if not any(start <= m.start() < end for start, end in flags)
        ]
        if hidden:
            first = hidden[0]
            decoded = InstructionText._decode_tags(raw)
            message = RULES["SUSPECT.AGENT.HIDDEN_TEXT.001"].message + f" {len(hidden)} found."
            if decoded:
                message += f' Unicode Tag characters in it spell: "{decoded[:120]}".'
            yield self._finding(
                "SUSPECT.AGENT.HIDDEN_TEXT.001",
                unit,
                ctx,
                first.start(),
                first.end(),
                message=message,
            )

        text = content.text
        fetches = list(_FETCH_EXEC.finditer(text))
        injection = next(
            (
                m
                for m in (*_INJECTION.finditer(text), *_INJECTION_INTL.finditer(text))
                if not InstructionText._quoted(text, m) and not InstructionText._forbidden(text, m)
            ),
            None,
        )
        exfil = any(_EXFIL_PATHS.search(line) and _SEND.search(line) for line in text.splitlines())
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
        if alarming is not None or (unknown is not None and (hidden or injection or exfil)):
            chosen = alarming or unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield self._finding("SUSPECT.AGENT.FETCH_EXEC.001", unit, ctx, start, end)
        elif fetches:
            chosen = unknown or fetches[0]
            start, end = InstructionText._byte_span(text, chosen)
            yield self._finding(
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
            yield self._finding("SUSPECT.AGENT.INJECTION_TEXT.001", unit, ctx, start, end)
        imported = _SENSITIVE_IMPORT.search(text)
        if imported is not None:
            start, end = InstructionText._byte_span(text, imported)
            yield self._finding("SUSPECT.AGENT.SENSITIVE_IMPORT.001", unit, ctx, start, end)
        remote = _REMOTE_INSTRUCTIONS.search(text)
        if remote is not None:
            start, end = InstructionText._byte_span(text, remote)
            alarming_host = InstructionText._alarming_fetch(remote.group(0))
            yield self._finding(
                "SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001",
                unit,
                ctx,
                start,
                end,
                severity=Severity.HIGH if alarming_host else None,
            )
        for line_match in re.finditer(r"[^\n]+", text):
            line = line_match.group(0)
            verdict = agent_config.CommandClassifier.classify(line)
            if (_EXFIL_PATHS.search(line) and _SEND.search(line)) or (
                verdict is not None and verdict.kind != "fetch-exec"
            ):
                start, end = InstructionText._byte_span(text, line_match)
                yield self._finding("SUSPECT.AGENT.CREDENTIAL_EXFIL.001", unit, ctx, start, end)
                break
        yield from self._threat_rules(
            unit,
            ctx,
            text,
            atr.TEXT_KINDS,
            instruction_file=True,
            corroborated=bool(hidden or injection or exfil or alarming is not None),
        )

    def _threat_rules(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        kinds: tuple[str, ...],
        *,
        within: str | None = None,
        instruction_file: bool = False,
        corroborated: bool = False,
    ) -> Iterator[Finding]:
        """The Agent Threat Rules that match `text`, one finding per ATR category.

        `within` is the file's text when `text` is a piece of it -- a hook's command, a tool's
        description -- so the finding points at the piece; otherwise `text` is the file itself.
        """
        matches = atr.AtrEngine.evaluate(text, kinds)
        by_category: dict[str, list[atr.AtrMatch]] = {}
        for match in matches:
            by_category.setdefault(match.rule.category, []).append(match)
        for category, found in by_category.items():
            rule_id = AgentRules.atr_rule_id(category)

            # Graded by ATR's own quality standard, from each rule's measured benign match
            # rate: a production-grade rule (0.5% or less) ATR also marks stable at critical or
            # high severity blocks; any other production-grade rule warns; a rule above ATR's
            # production line is recorded as an observation, never alone the reason a
            # repository is flagged.
            # An instruction file is prose written to the agent, and ATR's rules were written
            # for traffic: across 815 rules, each one's small error on such prose adds up. So
            # there a rule counts only if it matched at most `atr.INSTRUCTION_TOLERANCE` of the
            # real instruction files it was calibrated on, and it blocks only beside Cordon's own
            # evidence in the same file --
            # hidden text, override wording, a fetch-and-run, credentials moved. Tool
            # descriptions and commands, where text addressing the agent has no business, keep
            # ATR's grades.
            def counts(m: atr.AtrMatch) -> bool:
                if m.rule.grade != "production" or m.rule.severity in ("low", "info"):
                    return False
                return (
                    not instruction_file
                    or m.rule.instruction_hits is None
                    or m.rule.instruction_hits <= atr.INSTRUCTION_TOLERANCE
                )

            counted = [m for m in found if counts(m)]
            stable = [
                m
                for m in counted
                if m.rule.status == "stable"
                and m.rule.severity in ("critical", "high")
                and (corroborated or not instruction_file)
            ]
            if stable:
                severity = Severity.HIGH
            elif counted:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            found = stable or counted or found
            named = "; ".join(f"{m.rule.rule_id} ({m.rule.title.rstrip('.')})" for m in found[:4])
            more = len(found) - min(len(found), 4)
            message = (
                RULES[rule_id].message
                + f" Matched: {named}"
                + (f", and {more} more" if more > 0 else "")
                + f". Rules: {atr.RULE_URL.format(found[0].rule.rule_id)}"
            )
            first = found[0]
            if within is None:
                start = len(text[: first.start].encode("utf-8"))
                end = start + len(text[first.start : first.end].encode("utf-8"))
                yield self._finding(
                    rule_id, unit, ctx, start, end, message=message, severity=severity
                )
            else:
                # The matched words are found inside the file's text; the whole piece is the
                # fallback when JSON escaping has changed how they are spelled there.
                needle = text[first.start : first.end]
                if within.find(needle) < 0 and within.find(json.dumps(needle)[1:-1]) < 0:
                    needle = text
                yield self._at_text(
                    rule_id, unit, ctx, within, needle, message=message, severity=severity
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
                yield from self._threat_rules(unit, ctx, command, atr.TEXT_KINDS, within=text)
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
                yield self._at_text(rule_id, unit, ctx, text, command)
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
                yield self._at_text(
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
                yield self._at_text(
                    "POLICY.AGENT.WILDCARD_PERMISSION.001", unit, ctx, text, wildcard
                )
            if permissions.get("defaultMode") == "bypassPermissions":
                yield self._at_text(
                    "POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, "bypassPermissions"
                )
        if settings.get("enableAllProjectMcpServers") is True:
            yield self._at_text(
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
                yield self._at_text(
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
                    yield self._at_text(
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
                yield self._at_text("POLICY.AGENT.WIDE_DIRECTORY.001", unit, ctx, text, str(wide))
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
                    yield self._at_text(
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
            yield self._at_text("POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, yolo)

    def _vscode_settings(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = McpConfigs._json(unit.content)
        if isinstance(settings, dict) and settings.get("chat.tools.autoApprove") is True:
            yield self._at_text(
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
            yield from self._threat_rules(unit, ctx, launch, atr.TEXT_KINDS, within=text)
            verdict = agent_config.CommandClassifier.classify(launch)
            if verdict is not None or _FETCH_EXEC.search(launch):
                yield self._at_text(
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
                yield self._at_text("POLICY.AGENT.MCP_BROAD_SCOPE.001", unit, ctx, text, scope)
            spec = McpConfigs.launched_package(command, args)
            if spec is not None:
                ecosystem, package, pinned = spec
                imitated = agent_config.PackageLookalike.lookalike_of(package)
                if imitated is not None:
                    yield self._at_text(
                        "SUSPECT.MCP.LOOKALIKE.001",
                        unit,
                        ctx,
                        text,
                        package,
                        message=RULES["SUSPECT.MCP.LOOKALIKE.001"].message
                        + f" ({package} imitates {imitated})",
                    )
                if not pinned:
                    yield self._at_text(
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
                    yield self._at_text(
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
                    yield self._at_text(
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
                    yield self._at_text(
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
                    or _PLACEHOLDER.search(value.strip())
                ):
                    continue
                literal = value.strip()
                if block == "headers" and key.lower() == "authorization":
                    token = literal.split(" ", 1)[-1]
                    if _PLACEHOLDER.search(token) or token.startswith("${"):
                        continue
                elif not _SECRET_NAME.search(key) or "${" in literal:
                    continue
                yield self._at_text(
                    "SECRET.MCP.INLINE_CREDENTIAL.001", unit, ctx, text, literal, secret=True
                )

    _LIFECYCLE: Final = (
        "initializeCommand",
        "onCreateCommand",
        "updateContentCommand",
        "postCreateCommand",
        "postStartCommand",
        "postAttachCommand",
    )

    def _autorun(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """Commands an editor or agent runs when the folder is opened or the environment built."""
        document = McpConfigs._json(unit.content)
        if not isinstance(document, dict):
            return
        text = unit.content.text
        commands: list[tuple[str, str]] = []
        for task in document.get("tasks") or ():
            if not isinstance(task, dict):
                continue
            options = task.get("runOptions")
            if isinstance(options, dict) and options.get("runOn") == "folderOpen":
                command = task.get("command")
                arguments = [str(a) for a in task.get("args") or () if isinstance(a, str)]
                if isinstance(command, str):
                    commands.append(
                        ("a task that runs when the folder opens", " ".join([command, *arguments]))
                    )
        for key in self._LIFECYCLE:
            commands.extend(
                (f"the dev container's `{key}`", c)
                for c in McpConfigs._command_strings(document.get(key))
            )
        for key in ("install", "start"):
            commands.extend(
                (f"the agent environment's `{key}`", c)
                for c in McpConfigs._command_strings(document.get(key))
            )
        for terminal in document.get("terminals") or ():
            if isinstance(terminal, dict):
                commands.extend(
                    ("an agent environment terminal", c)
                    for c in McpConfigs._command_strings(terminal.get("command"))
                )
        for where, command in commands:
            verdict = agent_config.CommandClassifier.classify(command)
            if verdict is not None:
                yield self._at_text(
                    "MALWARE.AGENT.AUTORUN.001",
                    unit,
                    ctx,
                    text,
                    command.split(" ", 1)[0] if command not in text else command,
                    message=RULES["MALWARE.AGENT.AUTORUN.001"].message
                    + f" Here it is {where}, which {verdict.reason}.",
                )
                return

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
            yield self._at_text(
                "POLICY.AGENT.AUTO_APPROVE.001", unit, ctx, text, "danger-full-access"
            )
        providers = document.get("model_providers")
        for provider in providers.values() if isinstance(providers, dict) else ():
            base = provider.get("base_url") if isinstance(provider, dict) else None
            if isinstance(base, str) and agent_config.ApiTraffic.redirects_api(
                "OPENAI_BASE_URL", base
            ):
                yield self._at_text(
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
                yield self._at_text(
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
            yield self._at_text(
                "POLICY.AGENT.WILDCARD_PERMISSION.001", unit, ctx, unit.content.text, found.group(0)
            )

    def _remote_server(
        self, unit: FileUnit, ctx: ScanContext, text: str, url: str
    ) -> Iterator[Finding]:
        """A remote MCP server: how it is reached, where, and what its URL carries."""
        from cordon_scanner.intel.hosts import Destinations

        host = agent_config.ApiTraffic.host_of(url)
        local = host in _LOCAL_HOSTS
        if url.lower().startswith("http://") and not local:
            yield self._at_text("SUSPECT.MCP.INSECURE_TRANSPORT.001", unit, ctx, text, url)
        elif not local and (
            Destinations.destination_matcher().search(host.encode("utf-8", "replace"))
            or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
        ):
            yield self._at_text("SUSPECT.MCP.UNTRUSTED_REMOTE.001", unit, ctx, text, url)
        secret = agent_config.ServerExposure.credential_in_url(url)
        if secret is not None:
            yield self._at_text(
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
                yield self._finding(
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
            yield self._finding("SUSPECT.AGENT.CI_PROMPT_INJECTION.001", unit, ctx, start, end)

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
        yield self._finding(
            rule.rule_id,
            unit,
            ctx,
            start,
            end,
            message=f"{rule.message} Here: {known[first.group(1).lower()][0]} {'; '.join(what)}.",
            severity=Severity.CRITICAL if (secrets and writes and broad) else None,
        )

    # -- A5: editor extensions ---------------------------------------------------------------

    def _extension_recommendations(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        document = McpConfigs._json(unit.content)
        if not isinstance(document, dict):
            return
        named: list[str] = []
        named += [x for x in document.get("recommendations") or () if isinstance(x, str)]
        raw_customizations = document.get("customizations")
        customizations: dict[str, Any] = (
            raw_customizations if isinstance(raw_customizations, dict) else {}
        )
        raw_vscode = customizations.get("vscode")
        vscode: dict[str, Any] = raw_vscode if isinstance(raw_vscode, dict) else {}
        named += [x for x in vscode.get("extensions") or () if isinstance(x, str)]
        named += [
            x for x in document.get("extensions") or () if isinstance(x, str)
        ]  # legacy devcontainer
        for identifier in dict.fromkeys(named):
            yield from self._judge_extension(
                identifier.split("@", 1)[0], unit, ctx, recommended=True
            )

    def _vsix_manifest(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        manifest = McpConfigs._json(unit.content)
        if isinstance(manifest, dict) and manifest.get("publisher") and manifest.get("name"):
            yield from self._judge_extension(
                f"{manifest['publisher']}.{manifest['name']}", unit, ctx, recommended=False
            )

    def _judge_extension(
        self, identifier: str, unit: FileUnit, ctx: ScanContext, *, recommended: bool
    ) -> Iterator[Finding]:
        from cordon_scanner.intel import datafile

        lowered = identifier.strip().lower()
        if not _EXTENSION_ID.match(lowered):
            return
        intel = datafile.IntelDataFile.newest("vscode-extensions.json")
        how = "recommends" if recommended else "vendors the package of"
        removal = (intel.get("removed") or {}).get(lowered)
        if isinstance(removal, dict):
            reason = str(removal.get("reason", "")).lower()
            when = removal.get("removed", "")
            if any(r in reason for r in _MALWARE_REASONS):
                rule_id = "MALWARE.EXTENSION.REMOVED.001"
            elif any(r in reason for r in _SUSPECT_REASONS):
                rule_id = "SUSPECT.EXTENSION.REMOVED.001"
            else:
                rule_id = ""
            if rule_id:
                yield self._at_text(
                    rule_id,
                    unit,
                    ctx,
                    unit.content.text,
                    identifier,
                    message=f"This file {how} the editor extension {identifier}, which Microsoft removed from the "
                    f"Visual Studio Marketplace on {when} for: {removal.get('reason')}.",
                )
                return
        popular = set(intel.get("popular") or ())
        if not popular or lowered in popular:
            return
        lookalike = ExtensionNames._extension_lookalike(lowered, popular)
        if lookalike:
            yield self._at_text(
                "SUSPECT.EXTENSION.LOOKALIKE.001",
                unit,
                ctx,
                unit.content.text,
                identifier,
                message=f"This file {how} the editor extension {identifier}, which differs from the widely installed "
                f"{lookalike} by one character or by publisher alone -- the shape an impersonating extension takes.",
            )

    # -- Construction ----------------------------------------------------------------------

    def _at_text(
        self,
        rule_id: str,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        needle: str,
        *,
        message: str | None = None,
        severity: Severity | None = None,
        secret: bool = False,
    ) -> Finding:
        index = text.find(needle)
        if index < 0:
            index = text.find(json.dumps(needle)[1:-1])
        if index < 0:
            index = 0
        start = len(text[:index].encode("utf-8"))
        end = start + len(needle.encode("utf-8"))
        return self._finding(
            rule_id, unit, ctx, start, end, message=message, severity=severity, secret=secret
        )

    def _finding(
        self,
        rule_id: str,
        unit: FileUnit,
        ctx: ScanContext,
        start: int,
        end: int,
        *,
        message: str | None = None,
        severity: Severity | None = None,
        secret: bool = False,
    ) -> Finding:
        rule = RULES[rule_id]
        content = unit.content
        line = content.line_of(start)
        chosen = severity or rule.severity
        text = message or rule.message
        # Only the directory says test here. An agent reads its configuration by exact name,
        # so `settings.local.json` -- `local` marks a key file as non-production -- is the file
        # Claude Code loads, not a fixture.
        if rule.category not in (Category.MALICIOUS, Category.OPERATIONAL) and (
            SourcePaths.names_test_directory(content.path)
            or SourcePaths.test_material_glob(content.path)
        ):
            chosen = min(chosen, Severity.LOW)
            text += " It sits under a path that holds test material, so it is reported below its usual severity."
        snippet = content.line_text(line).strip()[:200]
        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=chosen,
            confidence=rule.confidence,
            message=text,
            location=Location(
                path=content.path,
                line=line,
                column=content.column_of(start),
                byte_start=start,
                byte_end=end,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(content.raw[start:end] or rule.rule_id.encode()),
                redaction=RedactionMode.MASKED,
                snippet=None
                if secret or rule_id == "SUSPECT.AGENT.HIDDEN_TEXT.001"
                else Redactor.mask(snippet),
                span=(start, end),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
            risk=ctx.scorer.score(chosen, rule.confidence, ScoringContext(in_install_hook=True)),
            detector=self.id,
            references=rule.references,
        )


class McpPackageDetector(BaseDetector):
    """A4: the packages MCP servers launch, read and scanned without being installed or run.

    Tools that inspect an MCP server by STARTING it run the thing they are checking: for a local
    server that is `npx -y some-package`, and a malicious package fires during the check. This
    reads the package instead, in this order:

    1. the copy already in the tree (`node_modules/<pkg>`, a virtualenv's `site-packages`), which
       is local and needs no network;
    2. with `--online`, the published archive, fetched from the registry's own host, verified
       against its digest, never installed and never run -- fetching names the package to the
       registry, which the default mode promises not to do;
    3. otherwise `OPERATIONAL.MCP.UNRESOLVED`: a server whose code was not read is never passed.

    Whatever it reads gets every rule, plus a tool-poisoning pass: hidden characters or
    agent-directed instructions in the tool descriptions the server will hand to the agent.
    """

    id = "mcp-packages"
    version = "0.2.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.VULNERABLE, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)
    MAX_REPORTED: Final = 20
    MAX_SOURCE_FILES: Final = 2000
    MAX_SOURCE_BYTES: Final = 1 << 20

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        rule = TOOL_POISONING_RULE
        return (
            DeclaredRule(
                id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                detector=McpPackageDetector.id,
                message=rule.message,
                remediation=rule.remediation,
                references=rule.references,
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit) or unit.content.is_binary:
            return ()
        path = unit.content.path.rpartition("!")[2]
        if not AgentPaths._paths_match(path, MCP_PATHS) or "!" in unit.content.path:
            return ()
        config = McpConfigs._json(unit.content)
        servers = (
            (config.get("mcpServers") or config.get("servers") or {})
            if isinstance(config, dict)
            else {}
        )
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for name, server in servers.items() if isinstance(servers, dict) else ():
            if not isinstance(server, dict) or not isinstance(server.get("command"), str):
                continue
            args = [str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))]
            spec = McpConfigs.launched_package(server["command"], args)
            if spec is None or spec[0] not in ("npm", "pypi") or (spec[0], spec[1]) in seen:
                continue
            if ctx.out_of_time():
                break
            seen.add((spec[0], spec[1]))
            findings.extend(self._examine(unit, ctx, str(name), spec[0], spec[1]))
        return findings

    # -- where the package comes from ------------------------------------------------------

    @staticmethod
    def _scan_root(ctx: ScanContext) -> Path | None:
        root = Path(ctx.repository.root) if ctx.repository is not None else None
        return root if root is not None and root.is_dir() else None

    def _local_copy(
        self, ctx: ScanContext, config_path: str, ecosystem: str, name: str
    ) -> list[Path]:
        """The package's own files in the tree, if it is installed there."""
        root = self._scan_root(ctx)
        if root is None:
            return []
        resolved_root = root.resolve()
        config_dir = (root / config_path).parent
        if ecosystem == "npm":
            for base in dict.fromkeys((config_dir, root)):
                candidate = base / "node_modules" / name
                if (candidate / "package.json").is_file() and candidate.resolve().is_relative_to(
                    resolved_root
                ):
                    return [candidate]
            return []
        wanted = re.sub(r"[-_.]+", "_", name).lower()
        for venv in (".venv", "venv", "env"):
            for dist_info in sorted((root / venv).glob("lib/python*/site-packages/*.dist-info"))[
                :5000
            ]:
                distribution = dist_info.name.removesuffix(".dist-info").rsplit("-", 1)[0]
                if re.sub(r"[-_.]+", "_", distribution).lower() != wanted:
                    continue
                site = dist_info.parent
                tops: set[str] = set()
                with contextlib.suppress(OSError):
                    for line in (dist_info / "RECORD").read_text(encoding="utf-8").splitlines():
                        top = line.split(",", 1)[0].split("/", 1)[0]
                        if top and top != ".." and not top.endswith((".dist-info", ".data")):
                            tops.add(top)
                return [
                    site / top
                    for top in sorted(tops)
                    if (site / top).exists()
                    and (site / top).resolve().is_relative_to(resolved_root)
                ]
        return []

    def _examine(
        self, unit: FileUnit, ctx: ScanContext, server: str, ecosystem: str, spec: str
    ) -> list[Finding]:
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        name, version = McpConfigs.split_spec(ecosystem, spec)
        local = self._local_copy(ctx, unit.content.path, ecosystem, name)
        if local:
            label = f"{ecosystem} package {name}, installed in this tree,"
            nested: tuple[Finding, ...] = tuple(
                f for target in local for f in McpServerSource._scan_path(target, ctx)
            )
            sources = list(
                McpServerSource._files_under(local, self.MAX_SOURCE_FILES, self.MAX_SOURCE_BYTES)
            )
            purl = f"pkg:{ecosystem}/{name}"
        elif not ctx.offline:
            try:
                archive = RegistryClient.package_archive(ecosystem, name, version)
            except RegistryError as exc:
                return [
                    self._unresolved(
                        unit, ctx, server, ecosystem, spec, f"it could not be fetched ({exc})"
                    )
                ]
            label = f"{ecosystem} package {archive.name}@{archive.version}, fetched (not installed, not run),"
            nested = McpServerSource._scan_archive_bytes(archive.filename, archive.data, ctx)
            sources = list(
                McpServerSource._archive_sources(
                    archive.filename, archive.data, self.MAX_SOURCE_FILES, self.MAX_SOURCE_BYTES
                )
            )
            purl = f"pkg:{ecosystem}/{archive.name}@{archive.version}"
        else:
            why = "it is not installed in this tree, and fetching it needs --online"
            return [self._unresolved(unit, ctx, server, ecosystem, spec, why)]
        reported = self._relay(unit, server, label, purl, spec, nested)
        reported.extend(self._tool_poisoning(unit, ctx, server, label, purl, spec, sources))
        return reported[: self.MAX_REPORTED]

    @staticmethod
    def _unresolved(
        unit: FileUnit, ctx: ScanContext, server: str, ecosystem: str, spec: str, why: str
    ) -> Finding:
        return AgentChainDetector()._at_text(
            "OPERATIONAL.MCP.UNRESOLVED",
            unit,
            ctx,
            unit.content.text,
            spec,
            message=f"MCP server {server!r} runs {ecosystem} package {spec}, whose code was not examined: {why}.",
        )

    # -- what was found in it ---------------------------------------------------------------

    @staticmethod
    def _anchor(unit: FileUnit, spec: str) -> int:
        index = unit.content.text.find(spec)
        return len(unit.content.text[: max(index, 0)].encode())

    def _relay(
        self,
        unit: FileUnit,
        server: str,
        label: str,
        purl: str,
        spec: str,
        nested: Iterable[Finding],
    ) -> list[Finding]:
        reported: list[Finding] = []
        start = self._anchor(unit, spec)
        for found in nested:
            if (
                found.category in (Category.OPERATIONAL, Category.POLICY)
                or found.severity < Severity.MEDIUM
            ):
                continue
            member = found.location.path.split("!", 1)[-1]
            reported.append(
                Finding(
                    rule_id=found.rule_id,
                    category=found.category,
                    severity=found.severity,
                    confidence=found.confidence,
                    message=f"MCP server {server!r} runs {label} and was examined. In {member}: {found.message}",
                    location=Location(
                        path=unit.content.path,
                        line=unit.content.line_of(start),
                        package=purl,
                        project=unit.project,
                    ),
                    evidence=Evidence(
                        kind=EvidenceKind.HASH,
                        match_hash=found.evidence.match_hash
                        or Evidence.hash_bytes(found.rule_id.encode()),
                        redaction=RedactionMode.HASH_ONLY,
                    ),
                    remediation=found.remediation,
                    explanation=Explanation(
                        summary=f"In MCP server package {purl}", matched_rule=found.rule_id
                    ),
                    risk=found.risk,
                    detector=self.id,
                    references=found.references,
                )
            )
            if len(reported) >= self.MAX_REPORTED:
                break
        return reported

    def _tool_poisoning(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        server: str,
        label: str,
        purl: str,
        spec: str,
        sources: list[tuple[str, str]],
    ) -> list[Finding]:
        """Hidden characters or agent-directed instructions in the text a server gives the agent."""
        start = self._anchor(unit, spec)
        for member, text in sources:
            for description in McpServerSource._tool_descriptions(text):
                hidden = HIDDEN.search(description.encode("utf-8"))
                injected = (
                    _INJECTION.search(description)
                    or _INJECTION_INTL.search(description)
                    or _FETCH_EXEC.search(description)
                )
                if not (hidden or injected):
                    continue
                severity = Severity.HIGH if hidden else Severity.MEDIUM
                confidence = Confidence.HIGH if hidden else Confidence.MEDIUM
                what = "invisible characters" if hidden else "instructions addressed to the agent"
                rule = TOOL_POISONING_RULE
                return [
                    Finding(
                        rule_id=rule.rule_id,
                        category=Category.SUSPICIOUS,
                        severity=severity,
                        confidence=confidence,
                        message=(
                            f"MCP server {server!r} runs {label} and a tool description in {member} "
                            f"carries {what}. The agent reads every tool description as context, so "
                            f"this text steers it without the user seeing it."
                        ),
                        location=Location(
                            path=unit.content.path,
                            line=unit.content.line_of(start),
                            package=purl,
                            project=unit.project,
                        ),
                        evidence=Evidence(
                            kind=EvidenceKind.HASH,
                            match_hash=Evidence.hash_bytes(description.encode("utf-8")),
                            redaction=RedactionMode.HASH_ONLY,
                        ),
                        remediation=rule.remediation,
                        explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
                        risk=ctx.scorer.score(severity, confidence),
                        detector=self.id,
                        references=rule.references,
                    )
                ]
        return []


TOOL_POISONING_RULE: Final = AgentRule(
    "SUSPECT.MCP.TOOL_POISONING.001",
    "An MCP server's tool description hides text or instructs the agent",
    Category.SUSPICIOUS,
    Severity.HIGH,
    Confidence.HIGH,
    "A tool description in the package an MCP server runs carries invisible characters (HIGH) or "
    "instructions addressed to the agent (MEDIUM). Agents read every tool description as context, "
    "so this steers the agent -- tool poisoning -- without the user seeing it.",
    "Do not run the server. Report the package to its registry if you did not write it.",
    (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
)

_QUOTED_DESCRIPTION: Final = re.compile(
    r"""(?:\bdescription\b[ \t]{0,8}[:=][ \t]{0,8}|\.describe\([ \t]{0,8})"""
    r"""(?:"(?P<dq>[^"\n]{8,4000})"|'(?P<sq>[^'\n]{8,4000})'|`(?P<bq>[^`]{8,4000})`)"""
)
"""A quoted `description` value in JS, TS or a JSON manifest. A quote escaped inside the text ends
the match early, which still leaves the part before it to be checked."""
_DOCSTRING_TOOL: Final = re.compile(
    r"@\w{1,40}(?:\.\w{1,40}){0,4}\.tool\b[^\n]{0,200}\n(?:[ \t]{0,40}@[^\n]{0,200}\n){0,5}"
    r"[ \t]{0,40}(?:async[ \t]{1,4})?def[ \t]{1,4}\w{1,80}\([^)]{0,500}\)[^:\n]{0,200}:[ \t]{0,8}\n?"
    r"[ \t]{0,40}(?P<doc>\"\"\"[^\x00]{0,4000}?\"\"\"|'''[^\x00]{0,4000}?''')"
)
_SOURCE_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".py", ".json")
_SERVER_SOURCE_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".py")
_MCP_SDK: Final = re.compile(
    r"\b(?:server|mcp|app)\.(?:tool|registerTool)\s*\(\s*\{?\s*(?:name\s*:|[\"'`])|\bnew\s+McpServer\s*\("
    r"|@modelcontextprotocol/sdk|\bfrom[ \t]+(?:mcp(?:\.server)?|fastmcp)\b[^\n]{0,40}\bimport\b"
    r"|^[ \t]*import[ \t]+(?:fastmcp|mcp)\b",
    re.MULTILINE,
)
"""An import of an MCP server SDK: the file declares tools an agent will be handed."""
_TOOL_NAME: Final = re.compile(
    r"""(?:\.tool\(\s*\{?\s*(?:name\s*:\s*)?|\bregisterTool\(\s*|\bname\s*[:=]\s*)"""
    r"""["'`](?P<name>[A-Za-z][\w.-]{1,80})["'`]"""
    r"""|@\w{1,40}(?:\.\w{1,40}){0,4}\.tool\b[^\n]{0,200}\n(?:[ \t]{0,40}@[^\n]{0,200}\n){0,5}"""
    r"""[ \t]{0,40}(?:async[ \t]{1,4})?def[ \t]{1,4}(?P<pyname>\w{1,80})"""
)


_OTHER_TOOL: Final = re.compile(
    r"(?i)\b(?:when(?:ever)?|before|after|instead\s+of)\b[^.\n]{0,40}\b(?:the\s+)?[\w.-]+\s+tool\b"
    r"|\b(?:any|every|all)\s+other\s+tools?\b"
)
_SECRECY: Final = re.compile(
    r"(?i)\b(?:never|do\s+not|don'?t|without)\s+(?:mention(?:ing)?|tell(?:ing)?|inform(?:ing)?|reveal(?:ing)?|"
    r"disclos(?:e|ing)|show(?:ing)?|notify(?:ing)?|alert(?:ing)?)\b"
)
_AGENT_TAG: Final = re.compile(
    r"(?i)<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|override|note\s+to\s+(?:the\s+)?(?:ai|assistant|agent))\b"
)


class McpServerSource:
    "An MCP server's own source: its tool descriptions, and scanning a fetched server."

    @staticmethod
    def _poisoned_description(description: str) -> str | None:
        """What makes a tool description an instruction to the agent rather than a description.

        A description says what the tool does. One that reaches for other tools, asks the agent to
        keep something from the user, names credential files, or wraps text in tags addressed to the
        model is steering the agent -- tool poisoning and shadowing -- whatever its wording.
        """
        if HIDDEN.search(description.encode("utf-8")):
            return "carries invisible characters"
        if _AGENT_TAG.search(description):
            return "wraps text in a tag addressed to the model"
        if _SECRECY.search(description):
            return "asks the agent to keep something from the user"
        if _OTHER_TOOL.search(description):
            return "tells the agent how to use other tools"
        if (
            _EXFIL_PATHS.search(description)
            or agent_config.CommandClassifier.classify(description) is not None
        ):
            return "points the agent at credential files or a command that moves them"
        return None

    @staticmethod
    def _tool_descriptions(text: str) -> Iterator[str]:
        """The tool descriptions a server source declares: quoted `description` values (JS, TS and
        JSON manifests) and the docstrings of decorated Python tool functions (FastMCP and kin)."""
        for match in _QUOTED_DESCRIPTION.finditer(text):
            yield match.group("dq") or match.group("sq") or match.group("bq") or ""
        for match in _DOCSTRING_TOOL.finditer(text):
            yield match.group("doc")[3:-3]

    @staticmethod
    def _files_under(
        roots: list[Path], max_files: int, max_bytes: int
    ) -> Iterator[tuple[str, str]]:
        count = 0
        for root in roots:
            candidates = (
                [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
            )
            for path in candidates:
                if count >= max_files:
                    return
                if path.suffix not in _SOURCE_SUFFIXES or path.stat().st_size > max_bytes:
                    continue
                count += 1
                with contextlib.suppress(OSError):
                    yield path.name, path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _archive_sources(
        filename: str, data: bytes, max_files: int, max_bytes: int
    ) -> Iterator[tuple[str, str]]:
        from cordon_scanner.archive.safe import ArchiveReader
        from cordon_scanner.core.errors import ArchiveError

        count = 0
        with contextlib.suppress(ArchiveError, ValueError, OSError):
            for member, payload in ArchiveReader.walk_archive(data, path=filename):
                if count >= max_files:
                    return
                if not member.endswith(_SOURCE_SUFFIXES) or len(payload) > max_bytes:
                    continue
                count += 1
                yield member.rsplit("!", 1)[-1], payload.decode("utf-8", errors="replace")

    @staticmethod
    def _scan_path(target: Path, ctx: ScanContext) -> tuple[Finding, ...]:
        """Scan a path with the same engine, offline, and return its findings."""
        from cordon_scanner.core.engine import Engine

        config = ctx.config.with_overrides(offline=True, intel_feed=False, use_cache=False)
        return Engine(config).scan(target).findings

    @staticmethod
    def _scan_archive_bytes(filename: str, data: bytes, ctx: ScanContext) -> tuple[Finding, ...]:
        """Scan downloaded archive bytes with the same engine, offline, and return its findings."""
        import tempfile

        suffix = "".join(Path(filename).suffixes[-2:]) or ".tgz"
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-") as directory:
            target = Path(directory) / f"package{suffix}"
            target.write_bytes(data)
            return McpServerSource._scan_path(target, ctx)


class McpConfigs:
    "MCP server declarations in every agent's configuration dialect, and what they launch."

    @staticmethod
    def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
        """`@scope/pkg@1.2.3` to (`@scope/pkg`, `1.2.3`); a floating spec gets version None."""
        if ecosystem == "npm":
            head, _, version = (
                spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
            )
            name = "@" + head if spec.startswith("@") else head
            exact = re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", version)
            return name, version if exact else None
        match = re.fullmatch(r"([\w.\-]+)(?:\[[^\]]*\])?(?:==|@)(\d[\w.\-+]*)", spec)
        if match:
            return match.group(1), match.group(2)
        return re.split(r"[\[=@<>~!]", spec, maxsplit=1)[0], None

    @staticmethod
    def launched_package(command: str, args: list[str]) -> tuple[str, str, bool] | None:
        """The (ecosystem, package spec, pinned) an MCP launch command downloads, if it does."""
        runner = command.rsplit("/", 1)[-1].lower().removesuffix(".cmd").removesuffix(".exe")
        rest = list(args)
        ecosystem = _RUNNERS.get(runner)
        if ecosystem is None and rest:
            ecosystem = _DLX_RUNNERS.get((runner, rest[0].lower()))
            if ecosystem is not None:
                rest = rest[1:]
                if runner == "uv" and rest and rest[0] == "run":
                    rest = rest[1:]
        if ecosystem is None:
            return None
        package = None
        skip_next = False
        for arg in rest:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-p", "--package", "--from", "--python", "--with"):
                if arg in ("-p", "--package", "--from"):
                    skip_next = False
                    continue
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            package = arg
            break
        if not package:
            return None
        if ecosystem == "npm":
            name, _, version = (
                package[1:].partition("@") if package.startswith("@") else package.partition("@")
            )
            if package.startswith("@"):
                name = "@" + name
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", version))
        else:
            match = re.fullmatch(r"([\w.\-\[\],]+?)(?:==|@)(\d[\w.\-+]*)", package)
            pinned = match is not None
        return ecosystem, package, pinned

    @staticmethod
    def mcp_servers(path: str, text: str) -> list[tuple[str, dict[str, Any]]]:
        """Every MCP server a configuration declares, as `(name, {command, args, url, env, ...})`.

        The agents disagree on the shape. Claude, Cursor, Gemini, Cline, Kiro and Amazon Q write
        `mcpServers: {name: {command, args}}`; VS Code writes `servers`; Zed writes `context_servers`
        with the launch under `command: {path, args}`; opencode writes `mcp` with `command` as one
        list; Codex writes TOML `[mcp_servers.name]`; Continue writes YAML with `mcpServers` as a
        list. A server missed for its dialect is a server never checked.
        """
        member = path.rpartition("!")[2]
        if member.endswith(".toml"):
            try:
                document: Any = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, ValueError):
                return []
            servers: Any = document.get("mcp_servers") if isinstance(document, dict) else None
        elif member.endswith((".yaml", ".yml")) or "/.continue/mcpServers/" in f"/{member}":
            return McpConfigs._continue_servers(text)
        else:
            document = McpConfigs._json_text(text)
            if not isinstance(document, dict):
                return []
            servers = (
                document.get("mcpServers")
                or document.get("servers")
                or document.get("context_servers")
                or document.get("mcp")
            )
        if not isinstance(servers, dict):
            return []
        out: list[tuple[str, dict[str, Any]]] = []
        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            server = dict(server)
            command = server.get("command")
            if isinstance(command, dict):  # Zed: command: {path, args, env}
                server["args"] = command.get("args") or server.get("args")
                server["env"] = command.get("env") or server.get("env")
                server["command"] = command.get("path")
            elif isinstance(command, list) and command:  # opencode: command: ["npx", "-y", "pkg"]
                server["command"], server["args"] = str(command[0]), [str(a) for a in command[1:]]
            if "environment" in server and "env" not in server:
                server["env"] = server["environment"]
            out.append((str(name), server))
        return out

    @staticmethod
    def _continue_servers(text: str) -> list[tuple[str, dict[str, Any]]]:
        """Continue's `mcpServers:` list, read for the four keys that matter without a YAML library:
        each `- name:` starts a server; `args` is a flow list or the block list beneath it."""
        servers: list[dict[str, Any]] = []
        in_block = False
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.match(r"^\s*mcpServers\s*:", line):
                in_block = True
                continue
            if not in_block:
                continue
            env_start = re.match(r"^(\s*)-?\s*env\s*:\s*$", line)
            if env_start is not None and servers:
                indent = len(env_start.group(1))
                env: dict[str, str] = {}
                for following in lines[index + 1 :]:
                    pair = re.match(r"^(\s+)([A-Za-z_][\w]*)\s*:\s*(.*?)\s*$", following)
                    if pair is None or len(pair.group(1)) <= indent:
                        break
                    env[pair.group(2)] = pair.group(3).strip("'\"")
                servers[-1]["env"] = env
                continue
            match = _YAML_KEY.match(line)
            if match is None:
                continue
            key, value = match.group(1), match.group(2).strip().strip("'\"")
            if (line.lstrip().startswith("-") and key == "name") or not servers:
                servers.append({})
            current = servers[-1]
            if key == "args":
                if value.startswith("["):
                    current["args"] = [
                        a.strip().strip("'\"") for a in value.strip("[]").split(",") if a.strip()
                    ]
                else:
                    items = []
                    for following in lines[index + 1 :]:
                        item = re.match(r"^\s*-\s+(.+?)\s*$", following)
                        if item is None or _YAML_KEY.match(following):
                            break
                        items.append(item.group(1).strip("'\""))
                    current["args"] = items
            else:
                current[key] = value
        return [
            (str(s.get("name", "server")), s) for s in servers if s.get("command") or s.get("url")
        ]

    @staticmethod
    def _json_text(text: str) -> Any:
        try:
            return json.loads(text)
        except ValueError:
            pass
        stripped = re.sub(
            r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*[\s\S]*?\*/', lambda m: m.group(1) or "", text
        )
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            return json.loads(stripped)
        except ValueError:
            return None

    @staticmethod
    def _command_strings(value: Any) -> list[str]:
        """A command field in any of the shapes the dev-container and agent-environment schemas allow:
        a string, an argument list, or an object of named commands."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [" ".join(str(a) for a in value)] if value else []
        if isinstance(value, dict):
            return [c for v in value.values() for c in McpConfigs._command_strings(v)]
        return []

    @staticmethod
    def _hook_commands(hooks: dict[str, Any]) -> list[str]:
        commands: list[str] = []
        for entries in hooks.values():
            for entry in entries if isinstance(entries, list) else ():
                if not isinstance(entry, dict):
                    continue
                for hook in entry.get("hooks") or ():
                    if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                        commands.append(hook["command"])
                if isinstance(entry.get("command"), str):
                    commands.append(entry["command"])
        return commands

    @staticmethod
    def _json(content: FileContent) -> Any:
        text = content.text
        try:
            return json.loads(text)
        except ValueError:
            pass
        # VS Code configuration is JSON with comments and trailing commas.
        stripped = re.sub(
            r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*[\s\S]*?\*/', lambda m: m.group(1) or "", text
        )
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            return json.loads(stripped)
        except ValueError:
            return None


_YAML_KEY: Final = re.compile(r"^\s*-?\s*(name|command|url|args)\s*:\s*(.*?)\s*$")


_QUOTES: Final = {"'": "'", '"': '"', "`": "`", "\u201c": "\u201d", "\u2018": "\u2019"}


_PROHIBITION: Final = re.compile(
    r"(?i)\b(?:never|don'?t|do\s+not|must\s+not|should\s+not|avoid|no)\b"
)


class ExtensionNames:
    "Editor extension ids, versions and lookalikes."

    @staticmethod
    def _semver(ref: str) -> tuple[int, int, int] | None:
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", ref)
        return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None

    @staticmethod
    def _extension_lookalike(identifier: str, popular: set[str]) -> str | None:
        """A popular extension this id imitates: the same name under another publisher, or one edit away."""
        publisher, _, name = identifier.partition(".")
        for candidate in sorted(popular):
            other_publisher, _, other_name = candidate.partition(".")
            if (
                len(other_name) >= 5
                and name == other_name
                and publisher != other_publisher
                and ExtensionNames._edit_distance(publisher, other_publisher) <= 2
            ):
                return candidate
            if len(candidate) >= 8 and ExtensionNames._edit_distance(identifier, candidate) == 1:
                return candidate
        return None

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        """Damerau-Levenshtein (adjacent transposition), stopping early past 2."""
        if abs(len(a) - len(b)) > 2:
            return 3
        previous2: list[int] = []
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            current = [i]
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
                if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                    value = min(value, previous2[j - 2] + 1)
                current.append(value)
            if min(current) > 2:
                return 3
            previous2, previous = previous, current
        return previous[-1]


__all__ = ["AGENT_ACTIONS", "RULES", "AgentChainDetector", "McpConfigs", "McpPackageDetector"]
