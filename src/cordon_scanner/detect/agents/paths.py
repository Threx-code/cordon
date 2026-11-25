"""Where agents read configuration from, by path.

The instruction files, agent settings, MCP configurations, CI workflows, Codex configuration, plugin
marketplaces, custom commands and editor extension manifests the agent detectors read: each a file an
agent acts on with the developer's rights.
"""

from __future__ import annotations

from typing import Final

from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.files.instruction_paths import INSTRUCTION_PATHS

AGENT_SETTINGS_PATHS: Final = (
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    "**/managed-settings.json",
    # Hooks in the other agents that run them, in the same `{"hooks": {event: [...]}}` shape:
    # a Claude Code plugin's `hooks/hooks.json`, Cursor's and Windsurf's `hooks.json`, Gemini
    # CLI's settings, Kiro's hook files.
    "**/hooks/hooks.json",
    "**/.cursor/hooks.json",
    "**/.windsurf/hooks.json",
    "**/.gemini/settings.json",
    "**/.kiro/hooks/*",
)

VSCODE_SETTINGS_PATHS: Final = ("**/.vscode/settings.json",)

MCP_PATHS: Final = (
    "**/.mcp.json",
    "**/.cursor/mcp.json",
    "**/.vscode/mcp.json",
    "**/.gemini/settings.json",
    "**/.windsurf/mcp.json",
    "**/.roo/mcp.json",
    "**/claude_desktop_config.json",
    "**/mcp.json",
    "**/cline_mcp_settings.json",
    "**/.zed/settings.json",
    "**/opencode.json",
    "**/opencode.jsonc",
    "**/.codex/config.toml",
    "**/.continue/config.yaml",
    "**/.continue/mcpServers/*",
)

WORKFLOW_PATHS: Final = ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml")

CODEX_CONFIG_PATHS: Final = ("**/.codex/config.toml",)

MARKETPLACE_PATHS: Final = ("**/.claude-plugin/marketplace.json",)

COMMAND_PATHS: Final = (
    "**/.claude/commands/**",
    "**/.claude/agents/**",
    "**/.claude/skills/**/SKILL.md",
)

EXTENSION_PATHS: Final = (
    "**/.vscode/extensions.json",
    "**/.devcontainer.json",
    "**/.devcontainer/devcontainer.json",
    "**/.devcontainer/*/devcontainer.json",
    # A multi-root workspace's own recommendations (`"extensions": {"recommendations": [...]}`).
    "**/*.code-workspace",
)

GITPOD_PATHS: Final = ("**/.gitpod.yml", "**/.gitpod.yaml")
"""Gitpod installs `vscode.extensions` from Open VSX into every workspace it starts, by id, by
`id@version`, or by a URL to a .vsix."""

BREWFILE_PATHS: Final = (
    "**/Brewfile",
    "**/.Brewfile",
    "**/Brewfile.txt",
    "**/Brewfile.local",
    "**/Brewfile.symlink",
    "**/*.Brewfile",
)
"""`brew bundle` installs `vscode "publisher.name"` lines into VS Code, from a Brewfile by any of
the names the Homebrew reader knows (`HomebrewEcosystem.manifest_globs`)."""

VSIX_MANIFEST: Final = "extension/package.json"
"""The manifest inside a `.vsix`, read when the archive is expanded."""


class AgentPaths:
    """Whether a path is one of the places an agent reads configuration from."""

    @staticmethod
    def _paths_match(path: str, patterns: tuple[str, ...]) -> bool:
        return any(PathGlob.matches(path, pattern) for pattern in patterns)


__all__ = [
    "AGENT_SETTINGS_PATHS",
    "BREWFILE_PATHS",
    "CODEX_CONFIG_PATHS",
    "COMMAND_PATHS",
    "EXTENSION_PATHS",
    "GITPOD_PATHS",
    "INSTRUCTION_PATHS",
    "MARKETPLACE_PATHS",
    "MCP_PATHS",
    "VSCODE_SETTINGS_PATHS",
    "VSIX_MANIFEST",
    "WORKFLOW_PATHS",
    "AgentPaths",
]
