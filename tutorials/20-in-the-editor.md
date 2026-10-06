# 20 · Findings in the editor

> **For Cordon 0.5.2.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

The VS Code extension shows Cordon's findings where you are already looking: on the
line, with the fix beside it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│    install        pipx install cordon-scanner                            │
│                   then cordon-<version>.vsix from the release page       │
│                                                                          │
│    it runs        on opening a folder, on save, and on                   │
│                   'Cordon: Scan workspace'                               │
│                                                                          │
│    it never       sends anything anywhere, runs in a folder you have not │
│                   trusted, or lets a repository choose what it executes  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Settings

| setting | default | |
|---|---|---|
| `cordon.path` | `cordon-scanner` | machine setting only: a workspace cannot change it |
| `cordon.scanOnSave` | `true` | |
| `cordon.minimumSeverity` | `low` | findings below this are not shown |

Findings without a line -- repository-wide ones, or members of an archive -- go to
the **Cordon** output channel, and the status bar shows the count.
