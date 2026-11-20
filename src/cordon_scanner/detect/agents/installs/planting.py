"""Code that writes an instruction file into an agent's own place from an install or import path.

An agent reads its instructions from a few places on the machine it runs on: a skills folder, a rules folder, a
`CLAUDE.md` or `AGENTS.md`, the agent's settings. A package whose install script, or whose module at import, copies or
writes a file into one of them puts text in front of the agent that the user never opened. Skill installers do this on
purpose, so the act alone is a signal; with an order of the instruction surface in the file written or shipped, the
decide layer's composite (`decide/code_and_instructions.py`) counts it as the code half of the attack.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.agents.findings import AgentFinding

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.foundation.models import Finding

_MAX_CHARS: Final = 1_000_000
#: Where an agent reads what it is told.
_PLACE: Final = (
    r"(?:\.claude[\"'`/\\]{1,3}(?:skills|commands|agents|output-styles|settings(?:\.local)?\.json|CLAUDE\.md)|"
    r"CLAUDE(?:\.local)?\.md|AGENTS?\.md|GEMINI\.md|\.cursorrules|\.cursor[\"'`/\\]{1,3}(?:rules|mcp\.json)|"
    r"\.windsurf(?:rules|[\"'`/\\]{1,3}rules)|\.clinerules|copilot-instructions\.md|\.codex[\"'`/\\]|"
    r"\.gemini[\"'`/\\]|\.agents[\"'`/\\]|\.continue[\"'`/\\])"
)
#: A file copied, written, appended, linked or created.
_WRITE: Final = (
    r"(?:copyFile\w{0,8}|cpSync|\bcp\(|writeFile\w{0,8}|appendFile\w{0,8}|mkdirSync|renameSync|symlink\w{0,8}|"
    r"createWriteStream|shutil\.(?:copy\w{0,8}|move)|write_text|write_bytes|\bopen\([^)\n]{0,100}[\"'][wa]|"
    r"os\.(?:symlink|rename)|WriteFile|fs::(?:write|copy)|\bcp\s|\bln\s+-s|\btee\b|\s>>?\s{0,2}[\"'~$\w])"
)
_PLANTS: Final = re.compile(
    _WRITE + r"[\s\S]{0,300}?" + _PLACE + "|" + _PLACE + r"[\s\S]{0,300}?" + _WRITE,
    re.IGNORECASE,
)


class AgentPlanting:
    """`scan(unit, ctx)`: the finding for a file on an install or import path that writes into an agent's own place."""

    RULE: ClassVar[str] = "SUSPECT.AGENT.PLANTS_INSTRUCTIONS.001"
    SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".py",
        ".sh",
        ".bash",
    )

    @staticmethod
    def _on_path(unit: FileUnit, ctx: ScanContext) -> bool:
        path = unit.content.path
        return path.lower().endswith(AgentPlanting.SUFFIXES) and (
            path in ctx.install_entry_paths
            or path in ctx.install_hook_paths
            or path in ctx.import_entry_paths
        )

    @classmethod
    def scan(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """One finding per file: where the first write into an agent's place sits."""
        text = unit.content.text
        if len(text) > _MAX_CHARS or not cls._on_path(unit, ctx):
            return
        found = _PLANTS.search(text)
        if found is None:
            return
        start = len(text[: found.start()].encode("utf-8"))
        end = len(text[: found.end()].encode("utf-8"))
        yield AgentFinding.finding(cls.RULE, unit, ctx, start, end)


__all__ = ["AgentPlanting"]
