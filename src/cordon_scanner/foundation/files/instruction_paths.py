"""The paths an agent reads its instructions, rules, commands and prompts from, as globs.

Kept in the foundation layer so the scan's own counts and the agent detectors read one list.
"""

from __future__ import annotations

from typing import Final

INSTRUCTION_PATHS: Final = (
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/AGENT.md",
    "**/GEMINI.md",
    "**/.cursorrules",
    "**/.cursor/rules/**",
    "**/.windsurfrules",
    "**/.windsurf/rules/**",
    "**/.clinerules",
    "**/.clinerules/**",
    "**/.github/copilot-instructions.md",
    "**/.github/instructions/**",
    "**/.github/prompts/**",
    "**/SKILL.md",
    "**/.claude/commands/**",
    "**/.claude/agents/**",
    "**/.claude/skills/**",
    "**/.claude/output-styles/**",
    # Copilot's custom chat modes, agents and the rest of its prompt files.
    "**/.github/chatmodes/**",
    "**/.github/agents/**",
    # Cursor, Gemini CLI, opencode and Windsurf commands and workflows: prompts the agent runs.
    "**/.cursor/commands/**",
    "**/.gemini/commands/**",
    "**/.opencode/agent/**",
    "**/.opencode/command/**",
    "**/.windsurf/workflows/**",
    # Kiro, Amazon Q, JetBrains Junie, Augment, Trae, Roo, Continue, Zed and goose.
    "**/.kiro/steering/**",
    "**/.amazonq/rules/**",
    "**/.junie/**",
    "**/.augment-guidelines",
    "**/.augment/rules/**",
    "**/.trae/rules/**",
    "**/.roo/rules/**",
    "**/.roo/rules-*/**",
    "**/.continue/rules/**",
    "**/.continue/prompts/**",
    "**/.rules",
    "**/.goosehints",
)


__all__ = ["INSTRUCTION_PATHS"]
