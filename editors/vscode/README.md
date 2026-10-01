# Cordon for VS Code

Shows what [Cordon](https://github.com/Threx-code/cordon) finds in the open workspace — malicious
packages, install-time behaviour, agent and MCP configuration, secrets and vulnerable dependencies —
as editor diagnostics, with the fix beside each one.

It runs the `cordon-scanner` you installed (`pipx install cordon-scanner`), offline, and sends
nothing anywhere. It waits until you trust a folder before running anything over it, and the
scanner's path is a machine setting: a repository cannot choose what the extension executes.

Commands: **Cordon: Scan workspace**, **Cordon: Clear findings**. Settings: `cordon.path`,
`cordon.scanOnSave`, `cordon.minimumSeverity`.
