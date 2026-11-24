"""Whether a coding agent's own hook configuration runs Cordon's pre-tool hook.

An agent keeps its hooks in its settings as `{"hooks": {event: [{"matcher": ..., "hooks": [{"type": "command",
"command": ...}]}]}}`. Cordon's hook is installed for that agent only when one of those commands runs the Cordon scanner
with its `hook` argument: a command that merely mentions Cordon, or another tool's hook, does not count.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, ClassVar, Final

AGENT_PRODUCTS: Final = (
    "claude-code",
    "claude-desktop",
    "codex",
    "cursor",
    "gemini-cli",
    "windsurf",
)


class HookInstall:
    """Reads agent settings for Cordon's hook."""

    PROGRAMS: ClassVar[frozenset[str]] = frozenset({"cordon-scanner", "cordon"})
    ARGUMENT: ClassVar[str] = "hook"

    @classmethod
    def runs_cordon(cls, command: object) -> bool:
        """Whether one hook command runs the Cordon scanner's hook: the program is Cordon's and `hook` is one of its arguments."""
        if not isinstance(command, str):
            return False
        try:
            words = shlex.split(command)
        except ValueError:
            return False
        if not words:
            return False
        program = re.split(r"[\\/]", words[0])[-1].removesuffix(".exe")
        return program in cls.PROGRAMS and cls.ARGUMENT in words[1:]

    @classmethod
    def installed(cls, settings: object) -> bool:
        """Whether a settings document has a hook command that runs Cordon's hook, in any event."""
        events = settings.get("hooks") if isinstance(settings, dict) else None
        if not isinstance(events, dict):
            return False
        for entries in events.values():
            for entry in entries if isinstance(entries, list) else ():
                inner = entry.get("hooks") if isinstance(entry, dict) else None
                for hook in inner if isinstance(inner, list) else ():
                    if isinstance(hook, dict) and cls.runs_cordon(hook.get("command")):
                        return True
        return False

    @classmethod
    def by_product(cls, tools: set[str], documents: dict[str, list[Any]]) -> dict[str, bool]:
        """For each agent product found: whether any of its settings documents installs the hook."""
        return {
            tool: any(cls.installed(document) for document in documents.get(tool, ()))
            for tool in sorted(tools)
            if tool in AGENT_PRODUCTS
        }
