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
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import is_test_material

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
)
AGENT_SETTINGS_PATHS: Final = ("**/.claude/settings.json", "**/.claude/settings.local.json")
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
)
WORKFLOW_PATHS: Final = ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml")

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
    r"(?i)\b(?:ignore|disregard|forget|override)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b"
    r"[^\n]{0,20}\b(?:instructions?|rules|guidelines|directions|prompts?)\b"
    r"|\b(?:do not|don't|never)\s+(?:tell|inform|mention|show|reveal)[^\n]{0,20}\b(?:the\s+)?user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying)\s+(?:the\s+)?user\b"
    r"|\byou are now\b[^\n]{0,40}\b(?:mode|unrestricted|jailbroken|DAN)\b"
)
_FETCH_EXEC: Final = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:curl|wget)\b[^\n]{0,300}(?:\|\s*python3?\b(?![ \t]{1,8}-[cm]\b)|>\s*/tmp/[^\s]+\s*&&\s*(?:ba)?sh\b)"
    r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b"
)
_URL_HOST: Final = re.compile(r"(?i)https?://([a-z0-9.-]{1,253})(/[^\s|\"'`)]{0,200})?")
KNOWN_INSTALLERS: Final = (
    ("astral.sh", ""),
    ("sh.rustup.rs", ""),
    ("bun.sh", ""),
    ("deno.land", ""),
    ("get.docker.com", ""),
    ("get.pnpm.io", ""),
    ("install.python-poetry.org", ""),
    ("pyenv.run", ""),
    ("ollama.com", "/install.sh"),
    ("starship.rs", "/install.sh"),
    ("sdk.cloud.google.com", ""),
    ("cli.github.com", ""),
    ("raw.githubusercontent.com", "/homebrew/install/"),
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),
)
"""Official one-line installers of widely used developer tools, by host and path prefix. A skill or
`AGENTS.md` telling the agent to install uv from `astral.sh` is documentation of a setup step every
contributor runs; the same instruction naming any other host is the shape the malicious-skill
campaigns use, and keeps its full severity. Matched on the URL actually piped, never on a substring
elsewhere on the line."""


def _known_installer(command: str) -> bool:
    found = _URL_HOST.search(command)
    if found is None:
        return False
    host, path = found.group(1).lower(), (found.group(2) or "").lower()
    return any(
        (host == known or host.endswith("." + known)) and path.startswith(prefix)
        for known, prefix in KNOWN_INSTALLERS
    )


_SHORTENERS: Final = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "shorturl.at", "goo.gl"}
)
_RAW_IP_URL: Final = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_DECODED: Final = re.compile(r"(?i)\bbase64\s+(?:-d|--decode)\b")


def _alarming_fetch(command: str) -> bool:
    """A fetch-and-run whose destination or shape has no business in setup instructions."""
    from cordon_scanner.intel.hosts import destination_matcher

    raw = command.encode("utf-8", "replace")
    if _DECODED.search(command) or _RAW_IP_URL.search(command) or destination_matcher().search(raw):
        return True
    found = _URL_HOST.search(command)
    host = found.group(1).lower() if found else ""
    # `astral.sh.evil.example` is built to read as the official host it is not.
    lookalike = any(host.startswith(f"{known}.") for known, _ in KNOWN_INSTALLERS)
    return host in _SHORTENERS or lookalike


_EXFIL_PATHS: Final = re.compile(
    r"(?i)(?:~|\$HOME)/\.(?:ssh|aws|npmrc|pypirc|docker/config\.json|kube/config)|\.env\b|id_rsa|\bGITHUB_TOKEN\b"
)
_SEND: Final = re.compile(
    r"(?i)\b(?:send|post|upload|exfiltrate|forward|copy)\b[^\n]{0,80}\b(?:to|into)\b"
)

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


def agent_actions() -> dict[str, tuple[str, tuple[int, int, int] | None]]:
    """Action -> (agent name, first fixed version), from the intel file over the built-in table."""
    from cordon_scanner.intel import datafile

    known: dict[str, tuple[str, tuple[int, int, int] | None]] = {
        action: (agent, FIXED_IN.get(action)) for action, agent in AGENT_ACTIONS.items()
    }
    for action, entry in (datafile.newest("agent-actions.json").get("actions") or {}).items():
        if isinstance(entry, dict):
            fixed = _semver(str(entry.get("fixed") or ""))
            known[str(action).lower()] = (
                str(entry.get("agent") or action),
                fixed or known.get(str(action).lower(), ("", None))[1],
            )
    return known


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


def _rule(*args: Any, **kwargs: Any) -> AgentRule:
    return AgentRule(*args, **kwargs)


RULES: Final = {
    rule.rule_id: rule
    for rule in (
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        _rule(
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
        if _paths_match(path, INSTRUCTION_PATHS):
            findings.extend(self._instructions(unit, ctx))
        if _paths_match(path, AGENT_SETTINGS_PATHS):
            findings.extend(self._agent_settings(unit, ctx))
        if _paths_match(path, VSCODE_SETTINGS_PATHS):
            findings.extend(self._vscode_settings(unit, ctx))
        if _paths_match(path, MCP_PATHS):
            findings.extend(self._mcp(unit, ctx))
        if _paths_match(path, WORKFLOW_PATHS):
            findings.extend(self._workflow(unit, ctx))
        if _paths_match(path, EXTENSION_PATHS):
            findings.extend(self._extension_recommendations(unit, ctx))
        if path == VSIX_MANIFEST and ".vsix!" in unit.content.path.lower():
            findings.extend(self._vsix_manifest(unit, ctx))
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
            decoded = _decode_tags(raw)
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
        injection = _INJECTION.search(text)
        exfil = any(_EXFIL_PATHS.search(line) and _SEND.search(line) for line in text.splitlines())
        # HIGH where the instruction is the attack's shape: a destination with no business
        # serving an installer (a paste site, a tunnel, a webhook, a raw address, a shortener), a
        # decoded payload, or a file that also hides text, overrides the agent or moves
        # credentials. A skill installing a vendor's CLI from the vendor's host is setup the
        # agent runs when somebody invokes the skill, and is reported below the gate --
        # across the first 228 repositories that was seventeen blocking findings in seven,
        # every one a CLI install line.
        alarming = next((m for m in fetches if _alarming_fetch(m.group(0))), None)
        unknown = next((m for m in fetches if not _known_installer(m.group(0))), None)
        if alarming is not None or (unknown is not None and (hidden or injection or exfil)):
            chosen = alarming or unknown or fetches[0]
            start, end = _byte_span(text, chosen)
            yield self._finding("SUSPECT.AGENT.FETCH_EXEC.001", unit, ctx, start, end)
        elif fetches:
            chosen = unknown or fetches[0]
            start, end = _byte_span(text, chosen)
            yield self._finding(
                "SUSPECT.AGENT.FETCH_EXEC.001",
                unit,
                ctx,
                start,
                end,
                severity=Severity.MEDIUM,
                message=RULES["SUSPECT.AGENT.FETCH_EXEC.001"].message
                + (
                    " The script comes from the tool's own official installer host"
                    if unknown is None
                    else " It installs from a vendor host with nothing else in the file pointing at an attack"
                )
                + ", so this is reported below the default gate.",
            )
        if injection is not None:
            start, end = _byte_span(text, injection)
            yield self._finding("SUSPECT.AGENT.INJECTION_TEXT.001", unit, ctx, start, end)
        for line_match in re.finditer(r"[^\n]+", text):
            line = line_match.group(0)
            if _EXFIL_PATHS.search(line) and _SEND.search(line):
                start, end = _byte_span(text, line_match)
                yield self._finding("SUSPECT.AGENT.CREDENTIAL_EXFIL.001", unit, ctx, start, end)
                break

    # -- A2 ------------------------------------------------------------------------------

    def _agent_settings(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = _json(unit.content)
        if not isinstance(settings, dict):
            return
        text = unit.content.text
        hooks = settings.get("hooks")
        if isinstance(hooks, dict) and hooks:
            commands = [c for c in _hook_commands(hooks) if c]
            dangerous = next((c for c in commands if _FETCH_EXEC.search(c)), None)
            if dangerous is not None:
                yield self._at_text("MALWARE.AGENT.HOOK_FETCH_EXEC.001", unit, ctx, text, dangerous)
            elif commands:
                yield self._at_text("SUSPECT.AGENT.HOOK.001", unit, ctx, text, commands[0])
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

    def _vscode_settings(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        settings = _json(unit.content)
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
        config = _json(unit.content)
        if not isinstance(config, dict):
            return
        servers = config.get("mcpServers") or config.get("servers") or {}
        if not isinstance(servers, dict):
            return
        text = unit.content.text
        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            yield from self._mcp_server(unit, ctx, text, str(name), server)

    def _mcp_server(
        self, unit: FileUnit, ctx: ScanContext, text: str, name: str, server: dict[str, Any]
    ) -> Iterator[Finding]:
        url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
        if isinstance(url, str) and url.lower().startswith("http://"):
            host = url[7:].split("/", 1)[0].split("@")[-1].rsplit(":", 1)[0].lower()
            if host not in _LOCAL_HOSTS:
                yield self._at_text("SUSPECT.MCP.INSECURE_TRANSPORT.001", unit, ctx, text, url)

        command = server.get("command")
        args = [str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))]
        if isinstance(command, str):
            launch = " ".join([command, *args])
            if _FETCH_EXEC.search(launch):
                yield self._at_text(
                    "SUSPECT.MCP.SHELL_LAUNCH.001", unit, ctx, text, args[-1] if args else command
                )
            spec = launched_package(command, args)
            if spec is not None:
                ecosystem, package, pinned = spec
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
            elif command == "docker" and "run" in args:
                image = next(
                    (
                        a
                        for a in args[args.index("run") + 1 :]
                        if not a.startswith("-") and "=" not in a
                    ),
                    None,
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

    # -- A6 ------------------------------------------------------------------------------

    def _workflow(self, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        text = unit.content.text
        uses = list(re.finditer(r"(?m)^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w./-]+?)@([\w.\-]+)", text))
        known = agent_actions()
        agents = [m for m in uses if m.group(1).lower() in known]
        if not agents:
            return
        for match in agents:
            action, pin = match.group(1).lower(), match.group(2)
            fixed = known[action][1]
            version = _semver(pin)
            if fixed and (
                (version is not None and version < fixed) or pin.lower() in ("beta", "v0")
            ):
                start, end = _byte_span(text, match)
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
            start, end = _byte_span(text, injected)
            yield self._finding("SUSPECT.AGENT.CI_PROMPT_INJECTION.001", unit, ctx, start, end)

        triggers = _triggers(text)
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
        start, end = _byte_span(text, first)
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
        document = _json(unit.content)
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
        manifest = _json(unit.content)
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
        intel = datafile.newest("vscode-extensions.json")
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
        lookalike = _extension_lookalike(lowered, popular)
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
        secret: bool = False,
    ) -> Finding:
        index = text.find(needle)
        if index < 0:
            index = text.find(json.dumps(needle)[1:-1])
        if index < 0:
            index = 0
        start = len(text[:index].encode("utf-8"))
        end = start + len(needle.encode("utf-8"))
        return self._finding(rule_id, unit, ctx, start, end, message=message, secret=secret)

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
        if rule.category not in (Category.MALICIOUS, Category.OPERATIONAL) and is_test_material(
            content.path
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
        if not _paths_match(path, MCP_PATHS) or "!" in unit.content.path:
            return ()
        config = _json(unit.content)
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
            spec = launched_package(server["command"], args)
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
        from cordon_scanner.intel.registry_client import RegistryError, package_archive

        name, version = split_spec(ecosystem, spec)
        local = self._local_copy(ctx, unit.content.path, ecosystem, name)
        if local:
            label = f"{ecosystem} package {name}, installed in this tree,"
            nested: tuple[Finding, ...] = tuple(
                f for target in local for f in _scan_path(target, ctx)
            )
            sources = list(_files_under(local, self.MAX_SOURCE_FILES, self.MAX_SOURCE_BYTES))
            purl = f"pkg:{ecosystem}/{name}"
        elif not ctx.offline:
            try:
                archive = package_archive(ecosystem, name, version)
            except RegistryError as exc:
                return [
                    self._unresolved(
                        unit, ctx, server, ecosystem, spec, f"it could not be fetched ({exc})"
                    )
                ]
            label = f"{ecosystem} package {archive.name}@{archive.version}, fetched (not installed, not run),"
            nested = _scan_archive_bytes(archive.filename, archive.data, ctx)
            sources = list(
                _archive_sources(
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
            for description in _tool_descriptions(text):
                hidden = HIDDEN.search(description.encode("utf-8"))
                injected = _INJECTION.search(description) or _FETCH_EXEC.search(description)
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


def _tool_descriptions(text: str) -> Iterator[str]:
    """The tool descriptions a server source declares: quoted `description` values (JS, TS and
    JSON manifests) and the docstrings of decorated Python tool functions (FastMCP and kin)."""
    for match in _QUOTED_DESCRIPTION.finditer(text):
        yield match.group("dq") or match.group("sq") or match.group("bq") or ""
    for match in _DOCSTRING_TOOL.finditer(text):
        yield match.group("doc")[3:-3]


def _files_under(roots: list[Path], max_files: int, max_bytes: int) -> Iterator[tuple[str, str]]:
    count = 0
    for root in roots:
        candidates = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for path in candidates:
            if count >= max_files:
                return
            if path.suffix not in _SOURCE_SUFFIXES or path.stat().st_size > max_bytes:
                continue
            count += 1
            with contextlib.suppress(OSError):
                yield path.name, path.read_text(encoding="utf-8", errors="replace")


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


def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
    """`@scope/pkg@1.2.3` to (`@scope/pkg`, `1.2.3`); a floating spec gets version None."""
    if ecosystem == "npm":
        head, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
        name = "@" + head if spec.startswith("@") else head
        exact = re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", version)
        return name, version if exact else None
    match = re.fullmatch(r"([\w.\-]+)(?:\[[^\]]*\])?(?:==|@)(\d[\w.\-+]*)", spec)
    if match:
        return match.group(1), match.group(2)
    return re.split(r"[\[=@<>~!]", spec, maxsplit=1)[0], None


def _scan_path(target: Path, ctx: ScanContext) -> tuple[Finding, ...]:
    """Scan a path with the same engine, offline, and return its findings."""
    from cordon_scanner.core.engine import Engine

    config = ctx.config.with_overrides(offline=True, intel_feed=False, use_cache=False)
    return Engine(config).scan(target).findings


def _scan_archive_bytes(filename: str, data: bytes, ctx: ScanContext) -> tuple[Finding, ...]:
    """Scan downloaded archive bytes with the same engine, offline, and return its findings."""
    import tempfile

    suffix = "".join(Path(filename).suffixes[-2:]) or ".tgz"
    with tempfile.TemporaryDirectory(prefix="cordon-mcp-") as directory:
        target = Path(directory) / f"package{suffix}"
        target.write_bytes(data)
        return _scan_path(target, ctx)


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


def _semver(ref: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", ref)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None


def _extension_lookalike(identifier: str, popular: set[str]) -> str | None:
    """A popular extension this id imitates: the same name under another publisher, or one edit away."""
    publisher, _, name = identifier.partition(".")
    for candidate in sorted(popular):
        other_publisher, _, other_name = candidate.partition(".")
        if (
            len(other_name) >= 5
            and name == other_name
            and publisher != other_publisher
            and _edit_distance(publisher, other_publisher) <= 2
        ):
            return candidate
        if len(candidate) >= 8 and _edit_distance(identifier, candidate) == 1:
            return candidate
    return None


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


def _byte_span(text: str, match: re.Match[str]) -> tuple[int, int]:
    start = len(text[: match.start()].encode("utf-8"))
    return start, start + len(match.group(0).encode("utf-8"))


__all__ = [
    "AGENT_ACTIONS",
    "RULES",
    "AgentChainDetector",
    "McpPackageDetector",
    "launched_package",
    "split_spec",
]
