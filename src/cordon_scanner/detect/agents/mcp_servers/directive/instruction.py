"""The orders and tricks of the table read in an agent's instruction files.

An instruction file (CLAUDE.md, AGENTS.md, GEMINI.md, a skill's SKILL.md, `.cursorrules`, a rules
folder) is text the agent obeys with the developer's rights, so it is read whole for the classes of the
table that list the `instruction` surface: fetch a page and follow it, pipe a download into a shell,
switch off the permission and safety prompts, send the secrets to an address, hide what was done from the
user, a trigger phrase that arms a quiet action, add a git remote and push to it, edit the agent's own
settings. A rule written in a Markdown file is graded as documentation and cannot block, so the reading
is code; the grading is the table's, by where the file came from:

```
  a file that arrives inside an installed package, skill, archive or download
        block class ─────────────────────────────────────────────► blocks
        signal class: a cover and an act in the file ────────────► blocks, otherwise reported
  the scanned project's own file                                    always reported for review
```

A project writes its own instruction file for its own agent and may say any of this of itself (install
steps that pipe a download, a build agent told to skip prompts), so there one phrase is not conclusive.
A file that comes in with something installed is the author's, not the user's, and no such file of the
measured legitimate packages and skills carries a `block` class.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents.mcp_servers.directive.reader import DirectiveHit, McpDirectives
from cordon_scanner.detect.agents.mcp_servers.directive.surfaces import SurfaceText
from cordon_scanner.detect.agents.mcp_servers.directive.table import FILE_SURFACE, DirectiveTable

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.foundation.models import Finding

#: The most of an instruction file that is read.
_MAX_FILE: Final = 400_000
#: The kinds of file an instruction is written in. A folder an agent reads (`.claude/skills/`) also holds
#: the scripts beside an instruction, which are code and are read as code.
_TEXT_SUFFIXES: Final = frozenset({"", ".md", ".mdc", ".markdown", ".txt", ".toml"})
_OWN_FILE: Final = (
    " A file of the scanned project itself is reported for review, not blocked: it is the project's"
    " own instruction to its own agent."
)


class InstructionDirectives:
    @staticmethod
    def reads(path: str) -> bool:
        """Whether a file of an instruction folder is text an agent obeys, not a script beside it."""
        return PurePosixPath(path.replace("\\", "/")).suffix.lower() in _TEXT_SUFFIXES

    @staticmethod
    def hits(text: str) -> list[DirectiveHit]:
        """Each class of the table that applies to an instruction file, with the first phrase of it."""
        item = SurfaceText(FILE_SURFACE, text, 0, len(text), ("file",))
        found: list[DirectiveHit] = []
        for directive in DirectiveTable.classes():
            if FILE_SURFACE not in directive.surfaces:
                continue
            match = McpDirectives.matched(directive, text, _MAX_FILE)
            if match:
                found.append(DirectiveHit(directive, item, match.span()))
        return found

    @classmethod
    def findings(
        cls, unit: FileUnit, ctx: ScanContext, text: str, *, installed: bool
    ) -> Iterator[Finding]:
        """One finding for each class read. `installed` is whether the file arrives inside something
        installed (a package, a skill, an archive, a download); only then can it block."""
        if not cls.reads(unit.content.path):
            return
        found = cls.hits(text)
        for hit in found:
            rule = DirectiveTable.rule_id(FILE_SURFACE, hit.directive.id)
            yield McpDirectives.finding(
                rule,
                unit,
                ctx,
                text,
                hit,
                installed and McpDirectives.blocks(hit, found),
                note=" One phrase like this is not conclusive, so it is reported for review."
                if installed
                else _OWN_FILE,
            )


__all__ = ["InstructionDirectives"]
