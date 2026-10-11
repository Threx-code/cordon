"""The configuration that adds Cordon's MCP server to each agent, as each agent's documentation
gives its format (checked 2026-10-11).

`cordon-scanner mcp config --client <name>` prints one. Nothing here writes an agent's
configuration: changing what an agent runs is the user's decision, made by pasting or running it.
"""

from __future__ import annotations

import json
import shutil
from typing import Final

#: client -> (where it goes, how the workspace is named in that file, or "" when it has no variable)
CLIENTS: Final[dict[str, tuple[str, str]]] = {
    "claude-code": (
        "run in the project, or put the JSON in .mcp.json at its root",
        "${CLAUDE_PROJECT_DIR}",
    ),
    "claude-desktop": ("claude_desktop_config.json (Settings > Developer > Edit Config)", ""),
    "cursor": (
        ".cursor/mcp.json in the project, or ~/.cursor/mcp.json for every project",
        "${workspaceFolder}",
    ),
    "vscode": (
        ".vscode/mcp.json in the workspace, or the user configuration (MCP: Open User Configuration)",
        "${workspaceFolder}",
    ),
    "windsurf": (
        "~/.config/devin/mcp_config.json (Windows: %APPDATA%\\devin\\mcp_config.json)",
        "",
    ),
    "gemini": (
        "run in the project, or add to .gemini/settings.json or ~/.gemini/settings.json",
        "",
    ),
    "codex": ("run once, or add to ~/.codex/config.toml", ""),
    "zed": ("Zed settings.json", ""),
    "cline": ("cline_mcp_settings.json (MCP Servers > Configure)", ""),
    "continue": (".continue/mcpServers/cordon.yaml", "${{ workspaceFolder }}"),
    "jetbrains": (
        "Settings | Tools | AI Assistant | Model Context Protocol (MCP) > Add, as JSON",
        "",
    ),
}


class Clients:
    @staticmethod
    def command() -> str:
        """The executable to name: the full path when it is on PATH, so an agent launched without
        the user's shell PATH still finds it."""
        return shutil.which("cordon-scanner") or "cordon-scanner"

    @classmethod
    def snippet(cls, client: str, *, allow_online: bool = False) -> str:
        where, workspace = CLIENTS[client]
        command = cls.command()
        args = (
            ["mcp"]
            + (["--root", workspace] if workspace else [])
            + (["--allow-online"] if allow_online else [])
        )
        entry = {"command": command, "args": args}
        if client == "claude-code":
            body = (
                f"claude mcp add --scope project cordon -- {command} {' '.join(args)}\n\nor .mcp.json:\n"
                + json.dumps({"mcpServers": {"cordon": entry}}, indent=2)
            )
        elif client == "vscode":
            body = json.dumps({"servers": {"cordon": {"type": "stdio", **entry}}}, indent=2)
        elif client == "gemini":
            body = (
                f"gemini mcp add --scope project cordon {command} {' '.join(args)}\n\nor settings.json:\n"
                + json.dumps({"mcpServers": {"cordon": entry}}, indent=2)
            )
        elif client == "codex":
            toml_args = ", ".join(json.dumps(a) for a in args)
            body = f"codex mcp add cordon -- {command} {' '.join(args)}\n\nor config.toml:\n[mcp_servers.cordon]\ncommand = {json.dumps(command)}\nargs = [{toml_args}]"
        elif client == "zed":
            body = json.dumps({"context_servers": {"cordon": {**entry, "env": {}}}}, indent=2)
        elif client == "continue":
            lines = "\n".join(f"      - {json.dumps(a)}" for a in args)
            body = (
                "name: Cordon\nversion: 0.0.1\nschema: v1\nmcpServers:\n"
                f"  - name: cordon\n    type: stdio\n    command: {json.dumps(command)}\n    args:\n{lines}"
            )
        else:
            body = json.dumps({"mcpServers": {"cordon": entry}}, indent=2)
        notes = [f"# {client}: {where}"]
        if not workspace:
            notes.append(
                "# This agent starts the server in the project directory it opens; if it starts it elsewhere,\n"
                "# add  --root /path/to/project  to args so the tools may read the project."
            )
        return "\n".join(notes) + "\n" + body
