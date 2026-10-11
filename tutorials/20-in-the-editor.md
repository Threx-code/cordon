# 20 · Findings in the editor

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Cordon's findings where you are already looking -- on the line, with the fix beside it -- in VS
Code and the editors built on it, and in every JetBrains IDE. Both run the `cordon-scanner` you
installed; neither sends anything anywhere.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  install       pipx install cordon-scanner, then the extension for your editor   │
│                                                                                  │
│  VS Code       the Visual Studio Marketplace: "Cordon supply-chain scanner"      │
│  Cursor,       Open VSX, the same extension                                      │
│  Windsurf,                                                                       │
│  VSCodium                                                                        │
│  IntelliJ,     the JetBrains Marketplace: "Cordon Supply-Chain Scanner"          │
│  PyCharm,      (2025.1 and later)                                                │
│  WebStorm,                                                                       │
│  GoLand, ...                                                                     │
│  offline       the .vsix and the plugin .zip are on every release page           │
│                                                                                  │
│  it runs       on opening a project, after a save, and on demand                 │
│  it never      runs in a folder you have not trusted, or lets a repository       │
│                choose what it executes                                           │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## VS Code and its relatives

| setting | default | |
|---|---|---|
| `cordon.path` | `cordon-scanner` | machine setting only: a workspace cannot change it |
| `cordon.scanOnSave` | `true` | |
| `cordon.minimumSeverity` | `low` | findings below this are not shown |
| `cordon.mcp.enabled` | `true` | offer Cordon's MCP server to the editor's agents |
| `cordon.mcp.allowOnline` | `false` | machine setting only: let those tools use the network |

On VS Code 1.101 and later the extension also registers **Cordon's MCP server** with the editor,
so Copilot's agent mode and any other agent that reads VS Code's MCP servers can check packages,
install commands, skills and MCP servers before acting (tutorial 30) -- with no configuration
file. On an editor without that API, **Cordon: Show MCP configuration** prints what to add.

Findings without a line -- repository-wide ones, or members of an archive -- go to the
**Cordon** output channel, and the status bar shows the count.

## JetBrains IDEs

Findings are marked on their lines and listed in the **Cordon** tool window (double-click opens
the line). **Tools > Scan Project with Cordon** rescans; **Settings > Tools > Cordon** holds the
scanner's path, the minimum severity and rescan-on-save, kept with the IDE, never with a project.
**Tools > Copy Cordon MCP Configuration** puts the configuration for AI Assistant on the
clipboard, to paste under Settings > Tools > AI Assistant > Model Context Protocol (MCP).

Next: **[21 · Reviewing a dependency update](21-dependency-review.md)**.
