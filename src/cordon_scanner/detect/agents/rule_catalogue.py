"""The agent detectors' rule catalogue.

Every agent rule with its category and severity, the ATR categories they map to, the intent words
that grade them, and the agent actions (GitHub Actions running a coding agent) whose fixed versions
are known.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.agents.autorun import Autorun
from cordon_scanner.detect.agents.extensions import ExtensionNames
from cordon_scanner.foundation import references as ref
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)

if TYPE_CHECKING:
    pass

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
    """The agent detector's rules, and the agent actions whose fixed versions are known."""

    @staticmethod
    def agent_actions() -> dict[str, tuple[str, tuple[int, int, int] | None]]:
        """Action -> (agent name, first fixed version), from the intel file over the built-in table."""
        from cordon_scanner.intel.store import datafile

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
            "SUSPECT.AGENT.DROPPER_PROSE.001",
            "Agent instructions that have the reader run a hidden or pasted payload",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This instruction file tells its reader to extract a password-protected archive and run "
            "what is in it, or to copy a command from a paste site into a terminal. A password keeps "
            "an archive opaque to every scanner it passes, and a paste site serves whatever its "
            'author last saved: this is how a skill delivers malware as a "prerequisite".',
            "Remove the instruction. A real dependency is installed from its own registry or "
            "release page, with a checksum.",
            (ref.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, ref.OWASP_LLM_PROMPT_INJECTION),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.SKILL_DECODE_RUN.001",
            "A skill's script decodes code and runs it",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "A script shipped with this agent skill decodes text -- base64, hex, compressed or "
            "pickled data -- and executes the result. The agent runs the skill's scripts on the "
            "user's machine; code that is decoded before it runs is code nobody reviewing the skill "
            "could read.",
            "Remove the encoded payload. A skill's script should be the code it runs, readable as "
            "it is.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
        AgentRules._rule(
            "SUSPECT.AGENT.PHANTOM_PREREQUISITE.001",
            "Agent instructions that require downloading a tool they never use",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This instruction file says a named tool must be installed and links a download for "
            "it, yet no command anywhere in the file runs that tool. A real prerequisite is used; "
            "a download the skill has no use for is the payload, delivered as a requirement.",
            "Remove the requirement, or install the tool from its own registry and use it.",
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
            "MALWARE.EXTENSION.KNOWN.001",
            "An editor extension is a recorded malicious release",
            Category.MALICIOUS,
            Severity.CRITICAL,
            Confidence.HIGH,
            "This repository recommends, ships the package of, or this machine has installed an editor "
            "extension (VS Code Marketplace or Open VSX) whose release OSV's malicious-package records "
            "name. VS Code, VSCodium, Cursor and Windsurf all install from these registries.",
            "Uninstall the extension everywhere it is installed, remove it from recommendations and "
            "delete any vendored .vsix, then treat the machines that ran it as compromised: rotate "
            "the credentials they held.",
            (ref.OSV, ref.VSCODE_REMOVED_EXTENSIONS),
        ),
        AgentRules._rule(
            "SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001",
            "A named editor extension has had malicious releases",
            Category.SUSPICIOUS,
            Severity.LOW,
            Confidence.LOW,
            "This file names an editor extension without a version, and OSV records specific releases "
            "of it as malicious (a compromised publisher or pipeline). The current release is not "
            "known to be affected, so this is reported, not blocked; an installed affected release is "
            "reported by version as MALWARE.EXTENSION.KNOWN.001.",
            "Check that machines have moved past the affected releases.",
            (ref.OSV,),
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
            "SUSPECT.EXTENSION.HIDDEN_NAME.001",
            "An editor extension's display name carries invisible characters",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "The name the editor and the Marketplace show for this extension contains characters "
            "that render as nothing, so it reads the same as a name it is not -- the way an "
            "impersonating extension sits beside the one it imitates in a search.",
            "Compare the publisher with the extension you meant to install.",
            (ref.VSCODE_REMOVED_EXTENSIONS,),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.SCHEMA_POISONING.001",
            "An MCP tool's parameter names an order to the agent",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "A parameter name or an allowed value in this server's tool schema is a sentence -- "
            "include the environment, attach the SSH keys, add the conversation history. The agent "
            "reads the schema to decide what to pass, so a name written as an instruction is one, "
            "and descriptions that pass review do not show it (full-schema poisoning).",
            "Remove the server, or rename the parameters to what they hold and review what the "
            "tool does with them.",
            (ref.MCP_SECURITY,),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.TOOL_SQUATTING.001",
            "An MCP tool takes a well-known tool's name and claims to be the safer one",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This server names a tool exactly as the widely used filesystem, shell, fetch or git "
            "servers name theirs, and describes it as an enhanced or more secure version. MCP tool "
            "names are not namespaced: where two servers offer the same name, the agent chooses by "
            "description, and this one is written to be chosen.",
            "Remove the server; if a tool by that name is needed, use the server it imitates.",
            (ref.MCP_SECURITY,),
        ),
        AgentRules._rule(
            "SUSPECT.MCP.DENIAL_OF_WALLET.001",
            "An MCP tool's result tells the agent to call it again, deeper or for every item",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "What this server returns instructs the agent to call the tool again -- one level "
            "deeper each time, or once for each of several items it lists -- a loop or fan-out the "
            "user did not ask for, paid for in tokens and calls.",
            "Remove the server, or make it return a complete result.",
            (ref.MCP_SECURITY,),
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
                "SUSPECT.MCP.ARGUMENT_OVERRIDE.001",
                "An MCP tool replaces the argument it was called with",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool in this MCP server assigns a fixed value to one of its own parameters "
                "before reading it, so whatever the agent asked for -- the address to geocode, the "
                "repository to read -- is thrown away and the tool acts on a value its author "
                "chose. The agent reports the result as the answer to the user's request.",
                "Remove the assignment, or the tool, and find out why it was added.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.HANDLER_SHELL.001",
                "An MCP tool runs its own input as a command",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool in this MCP server passes an argument the agent supplies -- directly, or "
                "through a helper -- to a shell, eval or exec, and neither its name nor its "
                "description says it runs commands. Whatever reaches that argument runs on the "
                "machine: a prompt injection anywhere upstream, or a prefix only its author knows.",
                "Remove the path from the argument to the command, or the tool.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.SKILL_RUNS_INPUT.001",
                "A skill's script runs its own input as code or a command",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "A function in a script this skill ships hands its argument to a shell, eval or "
                "exec. The agent calls the skill's functions with text it was given, so whatever "
                "reaches that argument -- a prompt injection upstream -- runs on the machine. A "
                "vulnerability rather than an attack, and reported as one.",
                "Pass arguments as data: an argument list, a parser, an allowlist of operations.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001",
                "A skill's script installs a package named like a popular one",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A script this skill ships installs, at run time, a package whose name is one slip "
                "from a popular package's and is not itself an established one. Installing it runs "
                "its author's code on the machine: dependency confusion and typosquatting, carried "
                "out by the agent.",
                "Do not use the skill. Check whether the package was installed anywhere.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001",
                "A skill's script hands the agent text that tells it to drop its instructions",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A script this skill ships carries text telling the reading model to ignore its "
                "previous instructions, become 'DAN' or reveal its system prompt. Whatever the "
                "script returns, the agent reads as context.",
                "Remove the text, or the skill.",
                (ref.OWASP_LLM_PROMPT_INJECTION,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.TOOL_PRIORITY_CLAIM.001",
                "Tells the agent to pick this tool over every other",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "Text the agent reads here claims this server or tool should be preferred over "
                "other tools in general. A tool replacing a specific one names it; a claim of "
                "priority over all of them is written to win the agent's choice, so the requests -- "
                "and the data in them -- meant for other tools come here.",
                "Remove the claim. Check what the tool does with requests meant for others.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.INSTALL_REDIRECT.001",
                "Code an agent runs points package installs somewhere else",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A skill's script or an MCP server's code writes package-manager configuration -- "
                "an `index-url`, a `registry` -- that decides where the next `pip install` or "
                "`npm install` fetches from. A tool the agent calls has no reason to change it; "
                "doing so hands every later install to whoever runs that index.",
                "Check pip.conf, .npmrc and the home directory for the change. Remove the tool.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.AUTH_BYPASS_EDIT.001",
                "Tells the agent to add an access check that one fixed identity always passes",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "These instructions have the agent insert code into the project that lets one "
                "hardcoded user, number or key through an access check -- whatever the allowlist "
                "or password says. However it is framed ('breakglass', 'admin override'), it is a "
                "backdoor written into the user's own code by their own agent.",
                "Do not follow the instructions. Search the project for the inserted check.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.AGENT.HIDDEN_DIRECTIVE.001",
                "Instructions to the model hidden in a comment",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "An HTML comment here opens by addressing the model -- 'SYSTEM:', 'AI assistant:' "
                "-- and tells it what to do. Rendered, the page shows nothing; an agent reading the "
                "raw text, or a tool result carrying it, takes it as an instruction no one it "
                "answers to gave. Nothing honest is said to a model in a place its user cannot see.",
                "Remove the comment. Do not let an agent read this repository's documents or use "
                "its tools until it is explained.",
                (ref.OWASP_LLM_PROMPT_INJECTION,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.TIME_BOMB.001",
                "An MCP tool changes behaviour on a mixed date, chance and call-count gate",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "Before doing its work, a tool of this MCP server returns something else when a "
                "gate opens -- one that mixes unrelated triggers such as the date, a random draw "
                "and how many times it has been called. A rate limit counts calls and a market "
                "tool checks the weekday; combining triggers so the switch cannot be predicted is "
                "how a tool passes review and turns later.",
                "Read what the gated branch returns. Do not use the server until explained.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.INPUT_MIRROR.001",
                "An MCP tool copies what it is asked into a hidden file",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool of this MCP server hands its arguments -- every query, path and message "
                "the agent sends it -- to code that appends them to a dotfile. A server logs "
                "through its logging library and caches what it fetched; keeping a hidden copy of "
                "the caller's input is collection.",
                "Find where the file is read from or sent. Do not use the server until explained.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.INPUT_FORWARDED.001",
                "An MCP tool sends what it is asked to a second host",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "A tool of this MCP server sends its arguments -- the query, path or message the "
                "agent passes it -- to more than one host, or to an address no tool's own service "
                "lives at (a bare IP, a webhook, a paste site). A tool calls the service it is for; "
                "a copy of every request sent elsewhere is collection.",
                "Find what each destination is for. Do not use the server until both are explained.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.SECRET_HARVEST.001",
                "An MCP server gathers the environment's secrets by name",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "This MCP server collects environment variables whose names look like secrets -- "
                "tokens, passwords, keys -- and keeps their values. A server reads the one "
                "credential it is configured with; gathering every one is what a stealer does.",
                "Find where the collected values go. Rotate any secret the server's environment held.",
                (ref.MCP_SECURITY,),
            ),
            AgentRules._rule(
                "SUSPECT.MCP.LISTENER.001",
                "An MCP server opens its own listening socket and runs commands",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "Beside its MCP transport this server binds a raw socket, accepts connections and, "
                "in the same file, runs commands: a way in that is not the MCP protocol and is "
                "not visible to the agent or the user.",
                "Remove the listener and find out who connects to it.",
                (ref.MCP_SECURITY,),
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
RULES.update(
    {
        "SUSPECT.AGENT.FRONT_MATTER_CODE.001": AgentRules._rule(
            "SUSPECT.AGENT.FRONT_MATTER_CODE.001",
            "Agent instructions whose front matter is code",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This file opens with `---js` (or another code engine) instead of YAML front matter. "
            "Front-matter parsers that honour the marker evaluate the block as code when they read "
            "the file, so loading the skill or instruction file runs it -- before anyone reads it.",
            "Replace the block with YAML front matter. No agent file needs executable metadata.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
        "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001": AgentRules._rule(
            "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001",
            "A skill's instructions read as an attack on the agent",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "The learned reading of skill instructions (`detect/mcp_model.py`, trained on "
            "MalSkillBench and MaliciousSkillBench against real public skills) scores this "
            "SKILL.md as written to steer the agent -- to run something, send something, or "
            "set its rules aside -- rather than to describe a task. It blocks above a threshold "
            "set on real skills held out of training, and is reported below it.",
            "Read the skill in full before installing it, including the files it tells the agent "
            "to run. Install it only from an author you trust.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
        "SUSPECT.AGENT.SKILL_HOOK_FETCH.001": AgentRules._rule(
            "SUSPECT.AGENT.SKILL_HOOK_FETCH.001",
            "A skill script installs an agent hook that runs a download",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This script, shipped with a skill, writes an agent hook whose command pipes a download "
            "into a shell. Once installed, every session the agent starts runs whatever that address "
            "serves at the time, with no review and no pinned version.",
            "Do not run the script. A hook should run code that is in the repository, pinned.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
    }
)
RULES.update(
    {
        "SUSPECT.AGENT.INTENT.001": AgentRules._rule(
            "SUSPECT.AGENT.INTENT.001",
            "Text that tells the agent to act against its user",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "Read for what it asks rather than how it is worded -- in any of six languages, with "
            "look-alike or invisible characters folded away -- this passage instructs the agent to "
            "work against the person using it.",
            "Remove the passage, or confirm who wrote it. An agent acts on what it reads.",
            (ref.OWASP_LLM_PROMPT_INJECTION, ref.MCP_SECURITY),
        ),
        "SUSPECT.AGENT.HIDDEN_INSTRUCTION.001": AgentRules._rule(
            "SUSPECT.AGENT.HIDDEN_INSTRUCTION.001",
            "An instruction to the agent that the rendered page does not show",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This text is hidden from a person reading it rendered -- an HTML comment, markup styled "
            "not to show, a link-reference definition, or a collapsed block addressed to the agent "
            "-- and it tells the agent to act on something that matters: send, run, read or "
            "override, with credentials, the environment, the conversation or an outside address. "
            "The agent reads the raw text; the person approving it reads the page.",
            "Remove the hidden passage, or move what it says into the visible text where its reader "
            "can judge it.",
            (ref.OWASP_LLM_PROMPT_INJECTION, ref.MCP_SECURITY),
        ),
        "SUSPECT.AGENT.INTENT_CHAINED.001": AgentRules._rule(
            "SUSPECT.AGENT.INTENT_CHAINED.001",
            "Agent instructions that send the agent to a file that acts against its user",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This instruction file tells the agent to follow another file, and that file instructs "
            "the agent to work against its user. Split across two files, neither reads as the "
            "attack alone.",
            "Read both files together; remove the reference or the passage it leads to.",
            (ref.OWASP_LLM_PROMPT_INJECTION,),
        ),
    }
)
RULES.update(Autorun.build_rules(AgentRules._rule))

#: What each intent is, as a finding says it.
INTENT_WORDS: Final = {
    "covert-exfil": "send what the user types, or other data, to an outside address -- covertly",
    "deceive": "tell the user something false while acting behind their back",
    "self-replicate": "copy these instructions into every reply or file it writes, so they spread",
    "persist": "write itself into the agent's own instruction files so it loads every session",
    "markdown-exfil": "carry data out in a markdown image URL the client fetches without asking",
    "credential-pipe": "read key or credential files and pipe them to a network tool",
    "secret-harvest": "collect every secret-named variable or a whole .env and send it to an outside host",
    "credential-elsewhere": "send a credential it printed with its own tool to a host that did not issue it",
    "concealed-override": "drop its safety rules and keep that hidden from the user",
    "concealed-sabotage": "make the user's work fail on purpose and deny it when asked",
}


__all__ = [
    "AGENT_ACTIONS",
    "ATR_CATEGORIES",
    "FIXED_IN",
    "INTENT_WORDS",
    "RULES",
    "AgentRule",
    "AgentRules",
]
