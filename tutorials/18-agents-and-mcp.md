# 18 · AI agents, MCP servers and skills

> **For Cordon 0.5.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Coding agents read instruction files, launch MCP servers and run hooks -- all of it
configured by files committed to the repository. Whoever can change those files can
steer the agent. Cordon reads every one of them, for every agent in common use, and
never starts an agent or a server to do it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   instruction files    CLAUDE.md  AGENTS.md  GEMINI.md  .cursor/rules/   │
│                        .github/copilot-instructions.md  .github/agents   │
│                        .kiro/steering  .amazonq/rules  .junie  .roo  ... │
│                                                                          │
│   MCP servers          .mcp.json  .cursor/mcp.json  .vscode/mcp.json     │
│                        .zed/settings.json  opencode.json                 │
│                        .codex/config.toml  cline_mcp_settings.json       │
│                        .continue/mcpServers/*.yaml                       │
│                                                                          │
│   hooks & approvals    .claude/settings.json  hooks/hooks.json (plugins) │
│                        .cursor/hooks.json  .gemini/settings.json         │
│                                                                          │
│   agents in CI         claude-code-action, codex-action, gemini-cli ...  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Run it

```bash
cordon-scanner scan .                 # the agent chain is part of every scan
cordon-scanner scan . --online        # also fetch each MCP server's package and read
                                      # what it tells the model (tool poisoning)
```

## What it reports

```
┌──────────────────────────────────────────────────────────────────────────┐
│   hidden text          invisible Unicode Tag or bidi characters          │
│                        spelling an instruction nobody can see   BLOCKS   │
│                                                                          │
│   hook downloads       a hook that pipes a fetch into a shell   BLOCKS   │
│                                                                          │
│   auto-approve         bypassPermissions, Bash(*),                       │
│                        chat.tools.autoApprove                            │
│                                                                          │
│   MCP supply chain     npx -y pkg@latest (unpinned), plain-http remotes, │
│                        credentials written into the config               │
│                                                                          │
│   injection wording    'ignore previous instructions', 'don't tell the   │
│                        user' -- in eleven languages. A warning, not a    │
│                        block: wording alone is not proof.                │
└──────────────────────────────────────────────────────────────────────────┘
```

Invisible-text smuggling is reported in **any** file, not only agent files: an agent
told to read the README reads its hidden characters too.

## On a developer's laptop

`cordon-scanner agent inventory` lists the agents, MCP servers and skills configured
on this machine, from known config paths only, and `agent report` sends that list to
Cordon Cloud when the organisation has enabled it.

Next: **[19 · What changed since the last release](19-release-comparison.md)**.
