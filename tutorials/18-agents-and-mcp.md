# 18 · AI agents, MCP servers and skills

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

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
how often each one fires on ATR's benign corpus, and adds 4 of Cordon's own written in ATR's
format (`scripts/data/cordon-atr-rules.yaml`) for the shapes ATR's published evasion cases show
slipping past its rules: the same instruction in Spanish, French, German, Portuguese or Italian,
a keyword split by stray spaces, and a persona defined by having no safety rules. Each went
through exactly what an ATR rule goes through, and matched none of ATR's 13,311 benign samples
and none of 1,654 real instruction files. A rule follows the scan path ATR gives
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

## Offline: what the text asks for

Before any judge, the text is read for what it asks the agent to do, with no model and
no network. Rephrasing does not escape it, because the wording is not what is matched:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  SUSPECT.AGENT.INTENT.001                                                │
│     send what the user types to an outside address                       │
│     lie to the user while acting                                         │
│     copy itself into every reply                                         │
│     write itself into the agent's own instruction files                  │
│                                                                          │
│  SUSPECT.AGENT.INTENT_CHAINED.001                                        │
│     one file tells the agent to obey another, and the other asks for     │
│     one of the above: followed across files                              │
│                                                                          │
│  read in six languages, with look-alike, invisible and spaced-out        │
│  characters folded away first                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

It lifted the published Agent Threat Rules evasions caught from 72.3% to 80.6%, with
the catalogue's benign near-misses still 92.4% clean.

## Remote MCP servers, as they are served now

A tool description is an instruction to the agent, and a remote server decides it at
request time: a server reviewed on Monday can describe its tools differently on
Tuesday, and nothing in the repository changes.

```
   cordon-scanner agent mcp-approve        record what each remote server serves:
                                           .cordon/mcp-tools.json (commit it)
   cordon-scanner scan . --online          ask each server again and compare
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001   what it serves now asks the     │
│                                          agent to do something harmful   │
│  SUSPECT.MCP.TOOLS_CHANGED.001           a tool added, removed or        │
│                                          redescribed since approval      │
│  OPERATIONAL.MCP.LIVE_UNREAD.001         a server could not be asked;    │
│                                          the scan says so                │
└──────────────────────────────────────────────────────────────────────────┘
```

Only remote servers over https, only with `--online`, with no redirects and no
credential the configuration does not name. A local stdio server is never started:
asking it would mean running the package under review.

## On a developer's laptop

`cordon-scanner agent inventory` lists the agents, MCP servers and skills configured
on this machine, from known config paths only, and `agent report` sends that list to
Cordon Cloud when the organisation has enabled it.

Next: **[19 · What changed since the last release](19-release-comparison.md)**.
