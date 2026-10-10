# 27 · Every AI agent and MCP location

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Everything a repository can hand a coding agent, the exact paths Cordon reads for each,
and every rule that judges them. Rendered from the detector itself, so a location added to
the code appears here, and one that is not read never does. The walkthrough is tutorial 18.

```
   instruction files ──┐
   skills, commands ───┤
   settings and hooks ─┼──►  read, never run  ──►  Cordon's agent rules
   MCP configurations ─┤                           Agent Threat Rules
   files run on open ──┤                           intent, offline
   CI agent actions ───┘                           the judge, if asked
```

## Instruction files, skills and commands

Text an agent reads as its instructions. Checked for hidden characters, injection wording, remote instructions, what the text asks for, and the Agent Threat Rules.

| Path | Read by |
|---|---|
| `CLAUDE.md` | Claude Code |
| `CLAUDE.local.md` | Claude Code |
| `AGENTS.md` | Codex, Amp and AGENTS.md readers |
| `AGENT.md` | Codex, Amp and AGENTS.md readers |
| `GEMINI.md` | Gemini CLI |
| `.cursorrules` | Cursor |
| `.cursor/rules/**` | Cursor |
| `.windsurfrules` | Windsurf |
| `.windsurf/rules/**` | Windsurf |
| `.clinerules` | Cline |
| `.clinerules/**` | Cline |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `.github/instructions/**` | GitHub Copilot |
| `.github/prompts/**` | GitHub Copilot |
| `SKILL.md` | Claude Code and other skill readers |
| `.claude/commands/**` | Claude Code |
| `.claude/agents/**` | Claude Code |
| `.claude/skills/**` | Claude Code |
| `.claude/output-styles/**` | Claude Code |
| `.github/chatmodes/**` | GitHub Copilot |
| `.github/agents/**` | GitHub Copilot |
| `.cursor/commands/**` | Cursor |
| `.gemini/commands/**` | Gemini CLI |
| `.opencode/agent/**` | opencode |
| `.opencode/command/**` | opencode |
| `.windsurf/workflows/**` | Windsurf |
| `.kiro/steering/**` | Kiro |
| `.amazonq/rules/**` | Amazon Q |
| `.junie/**` | JetBrains Junie |
| `.augment-guidelines` | Augment |
| `.augment/rules/**` | Augment |
| `.trae/rules/**` | Trae |
| `.roo/rules/**` | Roo Code |
| `.roo/rules-*/**` | Roo Code |
| `.continue/rules/**` | Continue |
| `.continue/prompts/**` | Continue |
| `.rules` | Zed |
| `.goosehints` | goose |

## Settings and hooks

Configuration that decides what an agent may do, and hooks it runs on its own: permissions granted, commands run on events, approval switched off.

| Path | Read by |
|---|---|
| `.claude/settings.json` | Claude Code |
| `.claude/settings.local.json` | Claude Code |
| `managed-settings.json` | Claude Code (managed) |
| `hooks/hooks.json` | Claude Code plugins |
| `.cursor/hooks.json` | Cursor |
| `.windsurf/hooks.json` | Windsurf |
| `.gemini/settings.json` | Gemini CLI |
| `.kiro/hooks/*` | Kiro |
| `.codex/config.toml` | Codex |

## MCP servers

Every MCP configuration dialect. Each local server is resolved to the exact package it launches and read from the registry tarball; each remote one, with `--online`, is asked what it serves now (tutorial 18).

| Path | Read by |
|---|---|
| `.mcp.json` | every MCP client that reads a project file |
| `.cursor/mcp.json` | Cursor |
| `.vscode/mcp.json` | VS Code |
| `.gemini/settings.json` | Gemini CLI |
| `.windsurf/mcp.json` | Windsurf |
| `.roo/mcp.json` | Roo Code |
| `claude_desktop_config.json` | Claude Code |
| `mcp.json` | MCP clients |
| `cline_mcp_settings.json` | Cline |
| `.zed/settings.json` | Zed |
| `opencode.json` | opencode |
| `opencode.jsonc` | opencode |
| `.codex/config.toml` | Codex |
| `.continue/config.yaml` | Continue |
| `.continue/mcpServers/*` | Continue |

## Files that run when a folder opens

Commands an editor or agent runs without anyone typing them: tasks set to run on open, dev-container lifecycle commands, background-agent setup.

| Path | Read by |
|---|---|
| `.vscode/tasks.json` | VS Code |
| `.devcontainer/devcontainer.json` | Dev Containers |
| `.devcontainer.json` | Dev Containers |
| `.devcontainer/*/devcontainer.json` | Dev Containers |
| `.cursor/environment.json` | Cursor |

## Editor extensions

Extensions and plugins a repository asks to have installed, checked against the marketplaces' own malware and impersonation verdicts.

| Path | Read by |
|---|---|
| `.vscode/extensions.json` | VS Code |
| `.devcontainer.json` | Dev Containers |
| `.devcontainer/devcontainer.json` | Dev Containers |
| `.devcontainer/*/devcontainer.json` | Dev Containers |
| `*.code-workspace` | VS Code |
| `.gitpod.yml` | Gitpod |
| `.gitpod.yaml` | Gitpod |
| `Brewfile` | Homebrew, into VS Code |
| `.Brewfile` | Homebrew, into VS Code |
| `Brewfile.txt` | Homebrew, into VS Code |
| `Brewfile.local` | Homebrew, into VS Code |
| `Brewfile.symlink` | Homebrew, into VS Code |
| `*.Brewfile` | Homebrew, into VS Code |
| `.claude-plugin/marketplace.json` | Claude Code |

## Agents in CI

Workflow steps that run a coding agent, checked for untrusted triggers, write permissions and broad tools.

| Action | Agent |
|---|---|
| `anthropics/claude-code-action` | Claude Code |
| `anthropics/claude-code-base-action` | Claude Code |
| `google-github-actions/run-gemini-cli` | Gemini CLI |
| `openai/codex-action` | Codex |

## On a developer's laptop

`cordon-scanner agent inventory` reads these, and only these; `agent report` sends the list, never a file's contents. Paths shown for Linux; on macOS and Windows the application-support folder is used.

| Path | Tool | Kind |
|---|---|---|
| `~/.claude/settings.json` | claude-code | settings |
| `~/.claude/settings.local.json` | claude-code | settings |
| `~/.claude/CLAUDE.md` | claude-code | instructions |
| `~/.claude.json` | claude-code | claude-json |
| `~/.config/Claude/claude_desktop_config.json` | claude-desktop | mcp |
| `~/.cursor/mcp.json` | cursor | mcp |
| `~/.codeium/windsurf/mcp_config.json` | windsurf | mcp |
| `~/.gemini/settings.json` | gemini-cli | mcp |
| `~/.gemini/GEMINI.md` | gemini-cli | instructions |
| `~/.config/Code/User/settings.json` | vscode | settings |
| `~/.config/Code/User/mcp.json` | vscode | mcp |
| `~/.codex/config.toml` | codex | codex-toml |
| `~/.codex/AGENTS.md` | codex | instructions |
| `~/.npmrc` | npm | npmrc |
| `~/.config/pip/pip.conf` | pip | pip |
| `~/.pip/pip.conf` | pip | pip |

## Every agent rule

46 rules of Cordon's own, beside the Agent Threat Rules (tutorial 28 lists those too).

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.AGENT.AUTORUN.001` | critical | A command an editor or agent runs on its own attacks the machine |
| `MALWARE.AGENT.HOOK_EXFIL.001` | critical | An agent hook that sends credentials away or opens a remote shell |
| `MALWARE.AGENT.HOOK_FETCH_EXEC.001` | critical | An agent hook that fetches and executes remote code |
| `MALWARE.EXTENSION.KNOWN.001` | critical | An editor extension is a recorded malicious release |
| `MALWARE.EXTENSION.REMOVED.001` | critical | A recommended or vendored editor extension was removed from the Marketplace as malware |
| `OPERATIONAL.MCP.UNRESOLVED` | info | An MCP server package was not examined |
| `POLICY.AGENT.AUTO_APPROVE.001` | high | Agent confirmations switched off in committed settings |
| `POLICY.AGENT.MCP_BROAD_SCOPE.001` | medium | A filesystem MCP server given the whole disk or home directory |
| `POLICY.AGENT.WIDE_DIRECTORY.001` | medium | Agent given the whole disk or home directory to work in |
| `POLICY.AGENT.WILDCARD_PERMISSION.001` | medium | Agent permissions allow any shell command |
| `SECRET.MCP.INLINE_CREDENTIAL.001` | high | A credential written inline in an MCP configuration |
| `SUSPECT.AGENT.API_REDIRECT.001` | high | Agent API traffic redirected to a host that is not the provider |
| `SUSPECT.AGENT.ATR.AGENT_MANIPULATION.001` | medium | Text that impersonates an agent or hijacks the agent's task |
| `SUSPECT.AGENT.ATR.CONTEXT_EXFILTRATION.001` | medium | Text that asks an agent to move secrets or context off the machine |
| `SUSPECT.AGENT.ATR.DATA_POISONING.001` | medium | Text that plants triggers or false facts for an agent |
| `SUSPECT.AGENT.ATR.EXCESSIVE_AUTONOMY.001` | medium | Text that asks an agent to act without the user's confirmation |
| `SUSPECT.AGENT.ATR.MODEL_ABUSE.001` | medium | Text that turns an agent toward abuse of the model |
| `SUSPECT.AGENT.ATR.MODEL_SECURITY.001` | medium | Text that targets the model's weights or safety |
| `SUSPECT.AGENT.ATR.PRIVILEGE_ESCALATION.001` | medium | Text that asks an agent to widen its own permissions |
| `SUSPECT.AGENT.ATR.PROMPT_INJECTION.001` | medium | Text that tries to override an agent's instructions |
| `SUSPECT.AGENT.ATR.SKILL_COMPROMISE.001` | medium | A skill or plugin shaped like a known compromise |
| `SUSPECT.AGENT.ATR.TOOL_POISONING.001` | medium | Text that turns a tool into a channel for steering the agent |
| `SUSPECT.AGENT.CI_PROMPT_INJECTION.001` | high | Untrusted event text passed straight into an agent's prompt |
| `SUSPECT.AGENT.CI_UNTRUSTED_TRIGGER.001` | high | An AI agent in CI reads text an outsider can write |
| `SUSPECT.AGENT.CREDENTIAL_EXFIL.001` | critical | Agent instructions that move credentials somewhere |
| `SUSPECT.AGENT.FETCH_EXEC.001` | high | Agent instructions that fetch and execute remote code |
| `SUSPECT.AGENT.HIDDEN_TEXT.001` | high | Hidden characters in an agent instruction file |
| `SUSPECT.AGENT.HOOK.001` | medium | An agent hook committed to the repository |
| `SUSPECT.AGENT.INJECTION_TEXT.001` | medium | Instruction-like text aimed at a coding agent |
| `SUSPECT.AGENT.INTENT.001` | high | Text that tells the agent to act against its user |
| `SUSPECT.AGENT.INTENT_CHAINED.001` | high | Agent instructions that send the agent to a file that acts against its user |
| `SUSPECT.AGENT.PLUGIN_SOURCE.001` | high | Agent plugins installed from an unverified source |
| `SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001` | medium | An agent instruction file tells the agent to fetch and follow remote text |
| `SUSPECT.AGENT.SENSITIVE_IMPORT.001` | high | An agent instruction file imports a credential file |
| `SUSPECT.EXTENSION.LOOKALIKE.001` | medium | A recommended editor extension imitates a popular one |
| `SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001` | low | A named editor extension has had malicious releases |
| `SUSPECT.EXTENSION.REMOVED.001` | high | A recommended or vendored editor extension was removed from the Marketplace |
| `SUSPECT.MCP.CONTAINER_HOST_ACCESS.001` | high | An MCP server's container is given the host |
| `SUSPECT.MCP.ENV_INJECTION.001` | high | An MCP server's environment loads code into it before it starts |
| `SUSPECT.MCP.INSECURE_TRANSPORT.001` | high | A remote MCP server over plain HTTP |
| `SUSPECT.MCP.LOOKALIKE.001` | high | An MCP server package named like a popular one |
| `SUSPECT.MCP.SHELL_LAUNCH.001` | high | An MCP server launched through a shell that fetches code |
| `SUSPECT.MCP.TOOL_DESCRIPTION.001` | high | A tool in this repository's MCP server instructs the agent |
| `SUSPECT.MCP.UNPINNED.001` | medium | An MCP server launched from an unpinned package |
| `SUSPECT.MCP.UNTRUSTED_REMOTE.001` | high | A remote MCP server on a tunnel, paste or interaction host |
| `VULNERABLE.AGENT.ACTION_VERSION.001` | high | An AI agent action below its security fix |

Agent Threat Rules findings are reported in these categories: agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, model-security, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning.

Next: **[28 · Every rule](28-every-rule.md)**.
