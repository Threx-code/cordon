# 27 · Every AI agent and MCP location

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

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

327 rules of Cordon's own, beside the Agent Threat Rules (tutorial 28 lists those too).

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
| `SUSPECT.AGENT.AUTH_BYPASS_EDIT.001` | high | Tells the agent to add an access check that one fixed identity always passes |
| `SUSPECT.AGENT.CI_PROMPT_INJECTION.001` | high | Untrusted event text passed straight into an agent's prompt |
| `SUSPECT.AGENT.CI_UNTRUSTED_TRIGGER.001` | high | An AI agent in CI reads text an outsider can write |
| `SUSPECT.AGENT.CREDENTIAL_EXFIL.001` | critical | Agent instructions that move credentials somewhere |
| `SUSPECT.AGENT.DROPPER_PROSE.001` | high | Agent instructions that have the reader run a hidden or pasted payload |
| `SUSPECT.AGENT.FETCH_EXEC.001` | high | Agent instructions that fetch and execute remote code |
| `SUSPECT.AGENT.FRONT_MATTER_CODE.001` | high | Agent instructions whose front matter is code |
| `SUSPECT.AGENT.HIDDEN_DIRECTIVE.001` | high | Instructions to the model hidden in a comment |
| `SUSPECT.AGENT.HIDDEN_INSTRUCTION.001` | high | An instruction to the agent that the rendered page does not show |
| `SUSPECT.AGENT.HIDDEN_TEXT.001` | high | Hidden characters in an agent instruction file |
| `SUSPECT.AGENT.HOOK.001` | medium | An agent hook committed to the repository |
| `SUSPECT.AGENT.INJECTION_TEXT.001` | medium | Instruction-like text aimed at a coding agent |
| `SUSPECT.AGENT.INSTALL_REDIRECT.001` | high | Code an agent runs points package installs somewhere else |
| `SUSPECT.AGENT.INSTRUCTION_ADD_REMOTE.001` | high | An agent instruction file tells the agent to add a git remote and push to it |
| `SUSPECT.AGENT.INSTRUCTION_CONCEAL_ACTIONS.001` | high | An agent instruction file tells the agent to hide what it did from the user |
| `SUSPECT.AGENT.INSTRUCTION_DISABLE_SAFETY.001` | high | An agent instruction file tells the agent to turn off permission or safety prompts |
| `SUSPECT.AGENT.INSTRUCTION_EDIT_AGENT_SETTINGS.001` | high | An agent instruction file tells the agent to change its own permissions or hooks |
| `SUSPECT.AGENT.INSTRUCTION_FETCH_AND_OBEY.001` | high | An agent instruction file tells the agent to fetch a page and follow what it says |
| `SUSPECT.AGENT.INSTRUCTION_PIPE_TO_SHELL.001` | high | An agent instruction file tells the agent to pipe a download into a shell |
| `SUSPECT.AGENT.INSTRUCTION_SEND_SECRETS.001` | high | An agent instruction file tells the agent to send secrets to an address |
| `SUSPECT.AGENT.INSTRUCTION_TRIGGER_PHRASE.001` | high | An agent instruction file arms a quiet action on a trigger phrase |
| `SUSPECT.AGENT.INTENT.001` | high | Text that tells the agent to act against its user |
| `SUSPECT.AGENT.INTENT_CHAINED.001` | high | Agent instructions that send the agent to a file that acts against its user |
| `SUSPECT.AGENT.PHANTOM_PREREQUISITE.001` | high | Agent instructions that require downloading a tool they never use |
| `SUSPECT.AGENT.PLANTS_INSTRUCTIONS.001` | medium | A package's install or start-up code writes a file into an agent's own instruction place |
| `SUSPECT.AGENT.PLUGIN_SOURCE.001` | high | Agent plugins installed from an unverified source |
| `SUSPECT.AGENT.REMOTE_CONTROL.001` | high | A package drives a coding agent or a terminal and listens to a remote service, and reads an agent's history |
| `SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001` | medium | An agent instruction file tells the agent to fetch and follow remote text |
| `SUSPECT.AGENT.SENSITIVE_IMPORT.001` | high | An agent instruction file imports a credential file |
| `SUSPECT.AGENT.SKILL_CLAIM_MISMATCH.001` | high | Shipped agent instructions do what no description claims |
| `SUSPECT.AGENT.SKILL_DECODE_RUN.001` | high | A skill's script decodes code and runs it |
| `SUSPECT.AGENT.SKILL_DISGUISED_ARCHIVE.001` | high | A skill ships an archive under a name that says it is something else |
| `SUSPECT.AGENT.SKILL_HOOK_FETCH.001` | high | A skill script installs an agent hook that runs a download |
| `SUSPECT.AGENT.SKILL_INSTALLS_LOOKALIKE.001` | high | A skill's script installs a package named like a popular one |
| `SUSPECT.AGENT.SKILL_INSTRUCTIONS.001` | high | A skill's instructions read as an attack on the agent |
| `SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001` | high | A skill's script hands the agent text that tells it to drop its instructions |
| `SUSPECT.AGENT.SKILL_LISTENER.001` | high | A skill's script opens its own listening socket and runs commands |
| `SUSPECT.AGENT.SKILL_RUNS_INPUT.001` | medium | A skill's script runs its own input as code or a command |
| `SUSPECT.AGENT.TOOL_PRIORITY_CLAIM.001` | high | Tells the agent to pick this tool over every other |
| `SUSPECT.CI.DEVCONTAINER_FETCH.001` | low | A published package's dev-container fetches and runs code when a developer opens it |
| `SUSPECT.EXTENSION.ADDED_CODE.001` | medium | An installed editor extension holds code its signed package does not have |
| `SUSPECT.EXTENSION.HIDDEN_NAME.001` | medium | An editor extension's display name carries invisible characters |
| `SUSPECT.EXTENSION.LOOKALIKE.001` | medium | A recommended editor extension imitates a popular one |
| `SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001` | low | A named editor extension has had malicious releases |
| `SUSPECT.EXTENSION.REMOVED.001` | high | A recommended or vendored editor extension was removed from the Marketplace |
| `SUSPECT.MCP.ACCOUNT_ENUMERATION.001` | medium | An MCP server's source lists the machine's user accounts and who is logged in |
| `SUSPECT.MCP.AGENT_SAFETY_OFF.001` | medium | An MCP server's source switches off the permission checks of the agent or the editor |
| `SUSPECT.MCP.ANALYSIS_TOOL_NAMES.001` | high | An MCP server's source lists the tools used to analyse malware |
| `SUSPECT.MCP.ARGUMENT_OVERRIDE.001` | high | An MCP tool replaces the argument it was called with |
| `SUSPECT.MCP.BIND_SHELL.001` | medium | An MCP server's source listens for connections and hands them a shell |
| `SUSPECT.MCP.C2_DNS_TXT.001` | medium | An MCP server's source takes its orders from a DNS text record |
| `SUSPECT.MCP.C2_TELEGRAM.001` | high | An MCP server's source takes its orders from a Telegram bot |
| `SUSPECT.MCP.CHARCODE_BUILD.001` | high | An MCP server's source spells a string out in character codes |
| `SUSPECT.MCP.CLOUD_METADATA.001` | medium | An MCP server's source names a cloud instance's metadata service |
| `SUSPECT.MCP.CONTAINER_ESCAPE.001` | high | An MCP server's source reaches out of its container |
| `SUSPECT.MCP.CONTAINER_HOST_ACCESS.001` | high | An MCP server's container is given the host |
| `SUSPECT.MCP.DECODE_RUN.001` | medium | An MCP server's source decodes or decompresses a value and runs the result as a command or as code |
| `SUSPECT.MCP.DENIAL_OF_WALLET.001` | medium | An MCP tool's result tells the agent to call it again, deeper or for every item |
| `SUSPECT.MCP.DESCRIPTION_CONCEALMENT.001` | high | A tool description of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.DESCRIPTION_CONSENT_CLAIM.001` | high | A tool description of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.DESCRIPTION_CROSS_TOOL.001` | high | A tool description of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.DESCRIPTION_EXFIL_ORDER.001` | high | A tool description of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.DESCRIPTION_FAKE_APPROVAL.001` | high | A tool description of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.DESCRIPTION_FAKE_BOUNDARY.001` | high | A tool description of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.DESCRIPTION_FAKE_WARNING.001` | high | A tool description of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.DESCRIPTION_FETCHED.001` | medium | An MCP server's source takes the description of its own tool from a network answer |
| `SUSPECT.MCP.DESCRIPTION_HARVEST.001` | high | A tool description of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.DESCRIPTION_HIDDEN_HTML.001` | high | A tool description of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.DESCRIPTION_LINK_EXFIL.001` | high | A tool description of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.DESCRIPTION_MEMORY_WRITE.001` | high | A tool description of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.DESCRIPTION_MODE_CLAIM.001` | high | A tool description of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.DESCRIPTION_OTHER_AGENT_ORDER.001` | high | A tool description of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.DESCRIPTION_OUTPUT_HIDDEN.001` | high | A tool description of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.DESCRIPTION_OVERRIDE.001` | high | A tool description of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.DESCRIPTION_RECIPIENT_INJECTION.001` | high | A tool description of an MCP server tells the model to add a fixed address to what it sends |
| `SUSPECT.MCP.DESCRIPTION_RETRIEVAL_DIRECTIVE.001` | high | A tool description of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.DESCRIPTION_ROLE_MARKER.001` | high | A tool description of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.DESCRIPTION_SECRET_CALL.001` | high | A tool description of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.DESCRIPTION_SECRET_REQUEST.001` | high | A tool description of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.DESCRIPTION_SETTINGS_EDIT.001` | high | A tool description of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.DESCRIPTION_TERMINAL_ESCAPE.001` | high | A tool description of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.DESCRIPTION_TOOL_PRIORITY.001` | high | A tool description of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.DESCRIPTION_URGENCY_AUTHORITY.001` | high | A tool description of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.DESCRIPTION_URL_APPEND.001` | high | A tool description of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.DESCRIPTION_ZERO_WIDTH.001` | high | A tool description of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.DETACHED_CHILD.001` | medium | An MCP server's source starts a detached process from a temporary location |
| `SUSPECT.MCP.DOWNLOAD_RUN_TEMP.001` | high | An MCP server's source downloads a program and starts it from a temporary directory |
| `SUSPECT.MCP.ELICIT_CREDENTIAL.001` | medium | An MCP server asks the user for a credential through the protocol's own prompt |
| `SUSPECT.MCP.EMBEDDED_WASM.001` | medium | An MCP server's source carries a WebAssembly module inside a string |
| `SUSPECT.MCP.ENV_INJECTION.001` | high | An MCP server's environment loads code into it before it starts |
| `SUSPECT.MCP.ERROR_CONCEALMENT.001` | high | An error message of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.ERROR_CONSENT_CLAIM.001` | high | An error message of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.ERROR_CROSS_TOOL.001` | high | An error message of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.ERROR_EXFIL_ORDER.001` | high | An error message of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.ERROR_FAKE_APPROVAL.001` | high | An error message of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.ERROR_FAKE_BOUNDARY.001` | high | An error message of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.ERROR_FAKE_WARNING.001` | high | An error message of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.ERROR_HARVEST.001` | high | An error message of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.ERROR_HIDDEN_HTML.001` | high | An error message of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.ERROR_LINK_EXFIL.001` | high | An error message of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.ERROR_MEMORY_WRITE.001` | high | An error message of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.ERROR_MODE_CLAIM.001` | high | An error message of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.ERROR_OTHER_AGENT_ORDER.001` | high | An error message of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.ERROR_OUTPUT_HIDDEN.001` | high | An error message of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.ERROR_OVERRIDE.001` | high | An error message of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.ERROR_RETRIEVAL_DIRECTIVE.001` | high | An error message of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.ERROR_ROLE_MARKER.001` | high | An error message of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.ERROR_SECRET_CALL.001` | high | An error message of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.ERROR_SECRET_REQUEST.001` | high | An error message of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.ERROR_SETTINGS_EDIT.001` | high | An error message of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.ERROR_TERMINAL_ESCAPE.001` | high | An error message of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.ERROR_TOOL_PRIORITY.001` | high | An error message of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.ERROR_URGENCY_AUTHORITY.001` | high | An error message of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.ERROR_URL_APPEND.001` | high | An error message of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.ERROR_ZERO_WIDTH.001` | high | An error message of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.EXFIL_DNS.001` | high | An MCP server's source builds a DNS name out of data |
| `SUSPECT.MCP.EXFIL_DROP.001` | medium | An MCP server's source names an anonymous paste or file-drop service |
| `SUSPECT.MCP.EXFIL_EMAIL.001` | medium | An MCP server's source sends mail to an address written in the code |
| `SUSPECT.MCP.EXFIL_LOGGER.001` | high | An MCP server's source names an IP-logging link |
| `SUSPECT.MCP.EXFIL_PRESIGNED.001` | high | An MCP server's source uploads to a signed storage address written in the code |
| `SUSPECT.MCP.EXFIL_REPO.001` | medium | An MCP server's source files what it handles as a gist or an issue in a repository written in the code |
| `SUSPECT.MCP.EXFIL_TUNNEL.001` | medium | An MCP server's source names a tunnel, request-capture or interaction host |
| `SUSPECT.MCP.EXFIL_WEBHOOK.001` | high | An MCP server's source carries a chat webhook with its secret written in |
| `SUSPECT.MCP.FORK_BOMB.001` | medium | An MCP server's source contains a fork bomb |
| `SUSPECT.MCP.GATED_PAYLOAD.001` | medium | An MCP server's source holds a fetch-and-run or a send behind a call count, a date or a check for CI |
| `SUSPECT.MCP.HANDLER_SHELL.001` | high | An MCP tool runs its own input as a command |
| `SUSPECT.MCP.HOME_WIPE.001` | medium | An MCP server's source deletes the user's whole home directory |
| `SUSPECT.MCP.IDENTITY_GATE.001` | medium | An MCP server's source acts only on the machines whose host name or locale it checks |
| `SUSPECT.MCP.INPUT_DROPPED.001` | medium | An MCP tool posts what it is asked to an address written in its code |
| `SUSPECT.MCP.INPUT_FORWARDED.001` | high | An MCP tool sends what it is asked to a second host |
| `SUSPECT.MCP.INPUT_MIRROR.001` | high | An MCP tool copies what it is asked into a hidden file |
| `SUSPECT.MCP.INPUT_PROGRAM.001` | medium | An MCP tool starts the program its input names |
| `SUSPECT.MCP.INPUT_SHELL.001` | medium | An MCP tool hands its input to a shell as a command |
| `SUSPECT.MCP.INSECURE_TRANSPORT.001` | high | A remote MCP server over plain HTTP |
| `SUSPECT.MCP.ISSUE_TASKING.001` | high | An MCP server's source reads orders from the issues of a repository written in the code |
| `SUSPECT.MCP.K8S_SECRET_READ.001` | high | An MCP server's source reads the cluster's secrets with its own service-account token |
| `SUSPECT.MCP.LIBRARY_HIJACK.001` | medium | An MCP server's source plants a library or a search path for other programs |
| `SUSPECT.MCP.LISTENER.001` | high | An MCP server opens its own listening socket and runs commands |
| `SUSPECT.MCP.LOG_CONCEALMENT.001` | high | A progress or log notification of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.LOG_CONSENT_CLAIM.001` | high | A progress or log notification of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.LOG_CROSS_TOOL.001` | high | A progress or log notification of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.LOG_EXFIL_ORDER.001` | high | A progress or log notification of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.LOG_FAKE_APPROVAL.001` | high | A progress or log notification of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.LOG_FAKE_BOUNDARY.001` | high | A progress or log notification of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.LOG_FAKE_WARNING.001` | high | A progress or log notification of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.LOG_HARVEST.001` | high | A progress or log notification of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.LOG_HIDDEN_HTML.001` | high | A progress or log notification of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.LOG_LINK_EXFIL.001` | high | A progress or log notification of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.LOG_MEMORY_WRITE.001` | high | A progress or log notification of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.LOG_MODE_CLAIM.001` | high | A progress or log notification of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.LOG_OTHER_AGENT_ORDER.001` | high | A progress or log notification of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.LOG_OUTPUT_HIDDEN.001` | high | A progress or log notification of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.LOG_OVERRIDE.001` | high | A progress or log notification of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.LOG_RETRIEVAL_DIRECTIVE.001` | high | A progress or log notification of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.LOG_ROLE_MARKER.001` | high | A progress or log notification of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.LOG_SECRET_CALL.001` | high | A progress or log notification of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.LOG_SECRET_REQUEST.001` | high | A progress or log notification of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.LOG_SETTINGS_EDIT.001` | high | A progress or log notification of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.LOG_TERMINAL_ESCAPE.001` | high | A progress or log notification of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.LOG_TOOL_PRIORITY.001` | high | A progress or log notification of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.LOG_URGENCY_AUTHORITY.001` | high | A progress or log notification of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.LOG_URL_APPEND.001` | high | A progress or log notification of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.LOG_ZERO_WIDTH.001` | high | A progress or log notification of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.LOOKALIKE.001` | high | An MCP server package named like a popular one |
| `SUSPECT.MCP.LOOKALIKE.002` | high | This MCP server's own package is named like a popular one |
| `SUSPECT.MCP.NATIVE_FROM_TEMP.001` | high | An MCP server's source loads a module or a shared library from a temporary place or straight from the network |
| `SUSPECT.MCP.NOTIFICATION_FLOOD.001` | medium | An MCP server's source sends notifications to the client in a loop with no end |
| `SUSPECT.MCP.PACKAGE_TAMPER.001` | medium | An MCP server's source writes into the files of other installed packages |
| `SUSPECT.MCP.PASTE_TASKING.001` | high | An MCP server's source fetches a paste from a paste site and runs it |
| `SUSPECT.MCP.PRIVILEGE_GRANT.001` | medium | An MCP server's source grants itself administrator rights |
| `SUSPECT.MCP.PROCESS_MASQUERADE.001` | medium | An MCP server's source gives its process the name of a system service |
| `SUSPECT.MCP.PROMPT_CONCEALMENT.001` | high | A prompt template of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.PROMPT_CONSENT_CLAIM.001` | high | A prompt template of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.PROMPT_CROSS_TOOL.001` | high | A prompt template of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.PROMPT_EXFIL_ORDER.001` | high | A prompt template of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.PROMPT_FAKE_APPROVAL.001` | high | A prompt template of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.PROMPT_FAKE_BOUNDARY.001` | high | A prompt template of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.PROMPT_FAKE_WARNING.001` | high | A prompt template of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.PROMPT_HARVEST.001` | high | A prompt template of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.PROMPT_HIDDEN_HTML.001` | high | A prompt template of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.PROMPT_INJECTION.001` | high | An MCP prompt template carries a hidden or hostile order |
| `SUSPECT.MCP.PROMPT_LINK_EXFIL.001` | high | A prompt template of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.PROMPT_MEMORY_WRITE.001` | high | A prompt template of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.PROMPT_MODE_CLAIM.001` | high | A prompt template of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.PROMPT_OTHER_AGENT_ORDER.001` | high | A prompt template of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.PROMPT_OUTPUT_HIDDEN.001` | high | A prompt template of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.PROMPT_OVERRIDE.001` | high | A prompt template of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.PROMPT_RECIPIENT_INJECTION.001` | high | A prompt template of an MCP server tells the model to add a fixed address to what it sends |
| `SUSPECT.MCP.PROMPT_RETRIEVAL_DIRECTIVE.001` | high | A prompt template of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.PROMPT_ROLE_MARKER.001` | high | A prompt template of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.PROMPT_SECRET_CALL.001` | high | A prompt template of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.PROMPT_SECRET_REQUEST.001` | high | A prompt template of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.PROMPT_SETTINGS_EDIT.001` | high | A prompt template of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.PROMPT_TERMINAL_ESCAPE.001` | high | A prompt template of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.PROMPT_TOOL_PRIORITY.001` | high | A prompt template of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.PROMPT_URGENCY_AUTHORITY.001` | high | A prompt template of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.PROMPT_URL_APPEND.001` | high | A prompt template of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.PROMPT_ZERO_WIDTH.001` | high | A prompt template of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.RANSOM_NOTE.001` | medium | An MCP server's source carries a ransom note |
| `SUSPECT.MCP.RECON_BATTERY.001` | medium | An MCP server's source runs several commands that survey the machine |
| `SUSPECT.MCP.RESOURCE_CONCEALMENT.001` | high | A resource of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.RESOURCE_CONSENT_CLAIM.001` | high | A resource of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.RESOURCE_CROSS_TOOL.001` | high | A resource of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.RESOURCE_EXFIL_ORDER.001` | high | A resource of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.RESOURCE_FAKE_APPROVAL.001` | high | A resource of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.RESOURCE_FAKE_BOUNDARY.001` | high | A resource of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.RESOURCE_FAKE_WARNING.001` | high | A resource of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.RESOURCE_HARVEST.001` | high | A resource of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.RESOURCE_HIDDEN_HTML.001` | high | A resource of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.RESOURCE_INJECTION.001` | high | An MCP resource serves text that gives the agent orders |
| `SUSPECT.MCP.RESOURCE_LINK_EXFIL.001` | high | A resource of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.RESOURCE_MEMORY_WRITE.001` | high | A resource of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.RESOURCE_MODE_CLAIM.001` | high | A resource of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.RESOURCE_OTHER_AGENT_ORDER.001` | high | A resource of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.RESOURCE_OUTPUT_HIDDEN.001` | high | A resource of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.RESOURCE_OVERRIDE.001` | high | A resource of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.RESOURCE_RETRIEVAL_DIRECTIVE.001` | high | A resource of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.RESOURCE_ROLE_MARKER.001` | high | A resource of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.RESOURCE_SECRET_CALL.001` | high | A resource of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.RESOURCE_SETTINGS_EDIT.001` | high | A resource of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.RESOURCE_TERMINAL_ESCAPE.001` | high | A resource of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.RESOURCE_TOOL_PRIORITY.001` | high | A resource of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.RESOURCE_URGENCY_AUTHORITY.001` | high | A resource of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.RESOURCE_URL_APPEND.001` | high | A resource of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.RESOURCE_ZERO_WIDTH.001` | high | A resource of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.RESPONSE_RUN.001` | medium | An MCP server's source reads an answer from a host and runs it as a command |
| `SUSPECT.MCP.RESULT_CONCEALMENT.001` | high | A tool result of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.RESULT_CONSENT_CLAIM.001` | high | A tool result of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.RESULT_CROSS_TOOL.001` | high | A tool result of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.RESULT_EXFIL_ORDER.001` | high | A tool result of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.RESULT_FAKE_APPROVAL.001` | high | A tool result of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.RESULT_FAKE_BOUNDARY.001` | high | A tool result of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.RESULT_FAKE_WARNING.001` | high | A tool result of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.RESULT_HARVEST.001` | high | A tool result of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.RESULT_HIDDEN_HTML.001` | high | A tool result of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.RESULT_INJECTION.001` | high | An MCP tool returns text that gives the agent orders |
| `SUSPECT.MCP.RESULT_LINK_EXFIL.001` | high | A tool result of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.RESULT_MEMORY_WRITE.001` | high | A tool result of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.RESULT_MODE_CLAIM.001` | high | A tool result of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.RESULT_OTHER_AGENT_ORDER.001` | high | A tool result of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.RESULT_OUTPUT_HIDDEN.001` | high | A tool result of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.RESULT_OVERRIDE.001` | high | A tool result of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.RESULT_RECIPIENT_INJECTION.001` | high | A tool result of an MCP server tells the model to add a fixed address to what it sends |
| `SUSPECT.MCP.RESULT_RETRIEVAL_DIRECTIVE.001` | high | A tool result of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.RESULT_ROLE_MARKER.001` | high | A tool result of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.RESULT_SECRET_CALL.001` | high | A tool result of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.RESULT_SECRET_REQUEST.001` | high | A tool result of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.RESULT_SETTINGS_EDIT.001` | high | A tool result of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.RESULT_TERMINAL_ESCAPE.001` | high | A tool result of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.RESULT_TOOL_PRIORITY.001` | high | A tool result of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.RESULT_URGENCY_AUTHORITY.001` | high | A tool result of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.RESULT_URL_APPEND.001` | high | A tool result of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.RESULT_ZERO_WIDTH.001` | high | A tool result of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.REVERSE_SHELL.001` | medium | An MCP server's source opens a reverse shell |
| `SUSPECT.MCP.ROOTS_ESCAPE.001` | medium | An MCP server's source asks for the user's roots and then reads a credential file outside them |
| `SUSPECT.MCP.SAMPLING_ABUSE.001` | high | An MCP server uses the client's model as its own tool through sampling |
| `SUSPECT.MCP.SCHEMA_CONCEALMENT.001` | high | A tool parameter description of an MCP server tells the model to hide what it does from the user |
| `SUSPECT.MCP.SCHEMA_CONSENT_CLAIM.001` | high | A tool parameter description of an MCP server claims that the user already approved, or that no approval is needed |
| `SUSPECT.MCP.SCHEMA_CROSS_TOOL.001` | high | A tool parameter description of an MCP server tells the model how to use other tools or servers |
| `SUSPECT.MCP.SCHEMA_EXFIL_ORDER.001` | high | A tool parameter description of an MCP server tells the model to send what it handles to a web address |
| `SUSPECT.MCP.SCHEMA_FAKE_APPROVAL.001` | high | A tool parameter description of an MCP server poses as an approval prompt and asks the person for a reply |
| `SUSPECT.MCP.SCHEMA_FAKE_BOUNDARY.001` | high | A tool parameter description of an MCP server closes the client's framing of tool text or opens a system block of its own |
| `SUSPECT.MCP.SCHEMA_FAKE_WARNING.001` | high | A tool parameter description of an MCP server poses as a security warning and tells the person to run a command |
| `SUSPECT.MCP.SCHEMA_HARVEST.001` | high | A tool parameter description of an MCP server asks the model to hand over the conversation or its system prompt |
| `SUSPECT.MCP.SCHEMA_HIDDEN_HTML.001` | high | A tool parameter description of an MCP server hides an order in an HTML comment |
| `SUSPECT.MCP.SCHEMA_LINK_EXFIL.001` | high | A tool parameter description of an MCP server has the model render an image or link with its data in the address |
| `SUSPECT.MCP.SCHEMA_MEMORY_WRITE.001` | high | A tool parameter description of an MCP server tells the model to store an instruction in its memory or settings |
| `SUSPECT.MCP.SCHEMA_MODE_CLAIM.001` | high | A tool parameter description of an MCP server announces a developer, debug or admin mode in which the model's restrictions are off |
| `SUSPECT.MCP.SCHEMA_OTHER_AGENT_ORDER.001` | high | A tool parameter description of an MCP server gives orders to other agents, tells them to skip checks or demands their context |
| `SUSPECT.MCP.SCHEMA_OUTPUT_HIDDEN.001` | high | A tool parameter description of an MCP server tells the model not to show the user this output, note or instruction |
| `SUSPECT.MCP.SCHEMA_OVERRIDE.001` | high | A tool parameter description of an MCP server tells the model to drop its earlier instructions or to follow new ones |
| `SUSPECT.MCP.SCHEMA_POISONING.001` | high | An MCP tool's parameter names an order to the agent |
| `SUSPECT.MCP.SCHEMA_RECIPIENT_INJECTION.001` | high | A tool parameter description of an MCP server tells the model to add a fixed address to what it sends |
| `SUSPECT.MCP.SCHEMA_RETRIEVAL_DIRECTIVE.001` | high | A tool parameter description of an MCP server addresses the model that will retrieve it and orders it |
| `SUSPECT.MCP.SCHEMA_ROLE_MARKER.001` | high | A tool parameter description of an MCP server carries a chat-template role marker |
| `SUSPECT.MCP.SCHEMA_SECRET_CALL.001` | high | A tool parameter description of an MCP server sends the model to a tool call on a credential or key file |
| `SUSPECT.MCP.SCHEMA_SECRET_REQUEST.001` | high | A tool parameter description of an MCP server asks for the contents of a credential file or for the user's seed phrase, private key or master password |
| `SUSPECT.MCP.SCHEMA_SETTINGS_EDIT.001` | high | A tool parameter description of an MCP server tells the model to change its own settings, permissions or hooks |
| `SUSPECT.MCP.SCHEMA_TERMINAL_ESCAPE.001` | high | A tool parameter description of an MCP server carries a terminal escape that hides text, sets the clipboard or disguises a link |
| `SUSPECT.MCP.SCHEMA_TOOL_PRIORITY.001` | high | A tool parameter description of an MCP server says this tool must be called first, replaces other tools or is the same as an official one |
| `SUSPECT.MCP.SCHEMA_URGENCY_AUTHORITY.001` | high | A tool parameter description of an MCP server claims authority and threatens a deadline |
| `SUSPECT.MCP.SCHEMA_URL_APPEND.001` | high | A tool parameter description of an MCP server tells the model to add the conversation or a secret to a web address |
| `SUSPECT.MCP.SCHEMA_ZERO_WIDTH.001` | high | A tool parameter description of an MCP server carries a run of zero-width characters |
| `SUSPECT.MCP.SECRET_HARVEST.001` | high | An MCP server gathers the environment's secrets by name |
| `SUSPECT.MCP.SECURITY_TOOL_KILL.001` | high | An MCP server's source stops or blinds security software |
| `SUSPECT.MCP.SHELL_LAUNCH.001` | high | An MCP server launched through a shell that fetches code |
| `SUSPECT.MCP.SHELL_PIPE_DOWNLOAD.001` | medium | An MCP server's source downloads a script and runs it in one command |
| `SUSPECT.MCP.SPLIT_PAYLOAD.001` | medium | An MCP server's source joins pieces of an encoded string and decodes the whole |
| `SUSPECT.MCP.SUBSCRIPTION_CHANNEL.001` | medium | An MCP server's source carries data to the client inside the address of a resource update |
| `SUSPECT.MCP.TIME_BOMB.001` | high | An MCP tool changes behaviour on a mixed date, chance and call-count gate |
| `SUSPECT.MCP.TOOLS_REPLACED_AFTER_CALLS.001` | medium | An MCP server's source replaces a tool's description after a number of calls |
| `SUSPECT.MCP.TOOL_DESCRIPTION.001` | high | A tool in this repository's MCP server instructs the agent |
| `SUSPECT.MCP.TOOL_NAME_LOOKALIKE.001` | medium | An MCP tool is named one letter from a well-known tool |
| `SUSPECT.MCP.TOOL_SQUATTING.001` | high | An MCP tool takes a well-known tool's name and claims to be the safer one |
| `SUSPECT.MCP.TRACE_ERASE.001` | medium | An MCP server's source erases shell history or system logs |
| `SUSPECT.MCP.UNPINNED.001` | medium | An MCP server launched from an unpinned package |
| `SUSPECT.MCP.UNTRUSTED_REMOTE.001` | high | A remote MCP server on a tunnel, paste or interaction host |
| `SUSPECT.MCP.WEBSOCKET_C2.001` | high | An MCP server's source takes commands from a WebSocket it opens itself |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.001` | high | An MCP server's source schedules a job that downloads and runs a script |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.002` | high | An MCP server's source writes a launch agent or daemon that downloads and runs a script |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.003` | high | An MCP server's source writes a service unit that downloads and runs a script |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.004` | high | An MCP server's source adds a line to a shell start-up file that downloads and runs a script |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.005` | high | An MCP server's source plants a git hook that downloads and runs a script |
| `SUSPECT.PERSIST.WRITES_DOWNLOADER.006` | high | An MCP server's source writes an instruction file for the agent that tells it to download and run a script |
| `VULNERABLE.AGENT.ACTION_VERSION.001` | high | An AI agent action below its security fix |

Agent Threat Rules findings are reported in these categories: agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, model-security, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning.

Next: **[28 · Every rule](28-every-rule.md)**.
