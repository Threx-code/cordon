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
│   skills & commands    .claude/skills/*/SKILL.md  .claude/commands       │
│                        .claude/agents  plugin manifests                  │
│                                                                          │
│   MCP servers          .mcp.json  .cursor/mcp.json  .vscode/mcp.json     │
│                        .zed/settings.json  opencode.json                 │
│                        .codex/config.toml  cline_mcp_settings.json       │
│                        .continue/mcpServers/*.yaml                       │
│                        and the server's own source, when it is here      │
│                                                                          │
│   hooks & approvals    .claude/settings.json  hooks/hooks.json (plugins) │
│                        .cursor/hooks.json  .gemini/settings.json         │
│                        .vscode/tasks.json  .devcontainer  Cursor envs    │
│                                                                          │
│   agents in CI         claude-code-action, codex-action, gemini-cli ...  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Run it

```bash
cordon-scanner scan .                       # the agent chain is part of every scan
cordon-scanner scan . --online              # also fetch each MCP server's package and
                                            # read what it tells the model
cordon-scanner scan . --judge cordon-cloud  # also have a language model read the text
                                            # an agent is handed (see below)
```

## What it reports

```
┌──────────────────────────────────────────────────────────────────────────┐
│   what a config RUNS      a hook, MCP launch or autorun task that        │
│                           downloads and executes, sends files or the     │
│                           environment off the machine, or opens a        │
│                           reverse shell                          BLOCKS  │
│                                                                          │
│   where traffic GOES      an API base URL pointed at someone else's      │
│                           server -- every prompt and key goes there      │
│                           (CVE-2026-21852)                               │
│                                                                          │
│   what a server is GIVEN  the Docker socket or host root, environment    │
│                           injection (LD_PRELOAD, NODE_OPTIONS), plain    │
│                           http or unknown remotes, a lookalike of a      │
│                           well-known MCP package, scopes like `repo`     │
│                                                                          │
│   approvals               bypassPermissions, Bash(*), autoApprove,       │
│                           Codex full access, Gemini YOLO,                │
│                           enableAllProjectMcpServers                     │
│                                                                          │
│   tool poisoning          a tool description that addresses the model,   │
│                           steers other tools, asks for secrecy, or tells │
│                           the agent to read or send a credential file    │
│                                                                          │
│   hidden text             invisible Unicode Tag or bidi characters       │
│                           spelling an instruction nobody can see BLOCKS  │
│                                                                          │
│   threat wording          the Agent Threat Rules catalogue (below), and  │
│                           injection phrasing in eleven languages         │
└──────────────────────────────────────────────────────────────────────────┘
```

Invisible-text smuggling is reported in **any** file, not only agent files: an agent
told to read the README reads its hidden characters too.

## The Agent Threat Rules catalogue

[ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) is the open catalogue of AI
agent threats. Cordon carries 815 of its 825 rules, translated to Python and graded by
how often each one fires on ATR's benign corpus. A rule follows the scan path ATR gives
it (`scan_target`):

```
   skill, both      instruction files, skills, commands
   mcp, both        what an MCP server hands the model: tool descriptions, responses
   runtime          a running agent's behaviour -- not something a file shows
```

In an instruction file a rule must also be near-silent on real ones: measured over
1,263 public instruction files, a rule that fired on more than one of them only counts
with a second signal. Real `CLAUDE.md` files talk about credentials and tokens all the
time, and a warning on every project would teach people to ignore it.

## The judge: wording no rule anticipated

Rules match the wordings someone wrote down. `--judge` has a language model read the
same text and report passages written to subvert the agent. It adds findings and never
removes one.

```
   --judge cordon-cloud        recommended; after `cordon login`
   --judge anthropic           your own key (ANTHROPIC_API_KEY)
   --judge openai:<model>      or any compatible server (CORDON_JUDGE_URL)
   --judge ollama:<model>      local; nothing leaves the machine. A 7B model
                               caught 70 of 100 new wordings and flagged 11 of
                               75 hard benign texts: a floor, not a gate
```

- Only agent-facing text is sent, a piece at a time, never other source.
- The text is fenced as data, and a verdict counts only if it quotes evidence that is
  really in the text, so a model talked round by what it read adds nothing.
- A malicious verdict warns; `--judge-blocks` makes it fail the build.
- The report says which judge ran. One that could not be reached marks the scan
  incomplete, rather than passing it quietly.

## On a developer's laptop

`cordon-scanner agent inventory` lists the agents, MCP servers and skills configured
on this machine, from known config paths only, and `agent report` sends that list to
Cordon Cloud when the organisation has enabled it.

Next: **[19 · What changed since the last release](19-release-comparison.md)**.
