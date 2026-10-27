# 30 · Cordon for AI agents: the MCP server

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Coding agents install packages, load skills and add MCP servers on their own. `cordon-scanner mcp`
lets them ask Cordon first, over the Model Context Protocol, and get the same verdict the CLI, CI
and the editor give.

```
   agent: "npm install left-pad@1.3.0 reqeusts"
     │
     ├─► check_install_command ──► Cordon reads, never runs ──► block: 'reqeusts' is a typosquat
     │                                                           of 'requests'
     └─► tells the user, does not run the command
```

## Add it to your agent

`cordon-scanner mcp config --client <agent>` prints the exact configuration for that agent, with
the full path of your `cordon-scanner`:

| agent | where it goes |
|---|---|
| `claude-code` | `claude mcp add --scope project cordon -- cordon-scanner mcp`, or `.mcp.json` |
| `claude-desktop` | `claude_desktop_config.json` |
| `cursor` | `.cursor/mcp.json`, or `~/.cursor/mcp.json` for every project |
| `vscode` | `.vscode/mcp.json` -- or nothing: the Cordon extension registers it (tutorial 20) |
| `windsurf` | `~/.config/devin/mcp_config.json` |
| `gemini` | `gemini mcp add`, or `.gemini/settings.json` |
| `codex` | `codex mcp add`, or `~/.codex/config.toml` |
| `zed` | `context_servers` in Zed's settings |
| `cline` | `cline_mcp_settings.json` |
| `continue` | `.continue/mcpServers/cordon.yaml` |
| `jetbrains` | AI Assistant > Model Context Protocol (the Cordon plugin copies it for you) |

The server speaks both protocol eras: the current one (2026-07-28, no handshake) and the
`initialize` handshake of 2025-11-25 back to 2024-11-05, so it works with every agent in use.

## The tools

| before the agent... | tool | what it answers |
|---|---|---|
| installs a package | `check_package`, `check_packages` | malicious and vulnerable releases (and the fix version), typosquats, names AI assistants invent; online, the published code scanned |
| runs an install command | `check_install_command` | every package it names, a second index or custom registry, `curl \| sh` |
| picks a version | `get_package_advisories` | every advisory, which affect a version, which versions fix them |
| loads a skill | `check_skill` | malicious instructions, droppers, fake prerequisites, credential theft |
| follows an instruction file | `check_agent_file` | prompt injection, hidden characters, fetch-and-run, approval switched off |
| adds an MCP server | `check_mcp_server`, `check_mcp_tools` | its launch command and package, secrets in its config, poisoned tool descriptions |
| installs an extension | `check_ide_extension` | a `.vsix`, or an id fetched from Open VSX (digest-checked) or the Marketplace |
| writes a file | `scan_file_content` | a Dockerfile, workflow or manifest checked before it exists |
| reviews a project | `scan_path`, `find_secrets`, `list_dependencies`, `describe_repository`, `generate_sbom`, `review_dependency_changes`, `compare_releases`, `compare_with_baseline`, `list_suppressions` | the full scanner, on the workspace |
| looks wider | `scan_container_image`, `scan_machine`, `list_local_agents` | images, this machine's packages, its agents and MCP servers |
| explains | `explain_rule`, `search_rules`, `intel_status`, `server_status` | rules, intel freshness, what this server may do |

Every result carries a verdict: `block` (the scanner's own failure policy fails it -- do not
proceed), `warn`, `pass`, or `incomplete` (something could not be read: never a pass).

## What it will not do

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  never     installs, runs what it reads, writes into your project, or changes any    │
│            configuration -- every tool is read-only                                  │
│  reads     only the directories it was started with (--root; default the current     │
│            directory); a symlink out of them, `..`, ~ or /etc is refused             │
│  network   off by default. --allow-online lets tools ask registries; even then a     │
│            name an agent passes in may lead only to the public internet, never to    │
│            10.x, localhost or a cloud metadata address (--allow-private-network     │
│            lifts that for an intranet registry or MCP server)                        │
│  machine   reading this computer's packages and agent configs needs --allow-machine  │
│  quoted    text from scanned files is stripped of invisible characters and marked    │
│            as data, so a poisoned file cannot pass instructions through Cordon       │
│  bounded   a deadline per scan (--timeout), calls per minute (--rate), scans at once │
│            (--max-concurrent); a cancelled call ends its scan's processes            │
│  audit     --audit-log PATH: one line per call -- tool, verdict, duration, never the │
│            arguments                                                                 │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

A tool that needs a flag the server was not started with is not listed at all, so the agent never
sees an option it cannot use.

Next: **[31 · Rule files](31-rule-files.md)**.
