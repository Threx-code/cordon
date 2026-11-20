"""The orders and tricks an attacker writes into the text an MCP server hands the agent, read from a table.

`detect/data/mcp-directives.json` lists the classes of text an attacker writes for the model to read:
telling it to drop its instructions, to hide what it does, to treat an approval as given, to steer other
tools, to read a key file, to send what it handles to an address, to write into its memory, to render
an image whose address carries its data, a run of invisible characters, a terminal escape that hides
text, a fake security warning that has the person run a command. A class is one entry of the table
(its phrasing, what it does and why it matters, whether it blocks alone); a vocabulary change is a row.

Each class is read on every surface (`surfaces.py`: a tool's description, an argument's description,
its result, an error, a progress or log notification, a resource, a prompt) and gives one rule per
surface, so a finding says where the text sits. A text is read only where the server hands it to the
agent: inside a registration, or in a handler's own return, raise or notification.

```
  surface text ──► each class that applies to the surface ──► a phrase of the class matches
                                                                    │
        block class ───────────────────────────────────────────────►├─► blocks
        signal class ─ alone ──► reported for review                 │
                       an act and a cover in the same text ─────────►┘
```

A `block` class is one no legitimate server of the development sets carries. A `signal` class is one
such a server does: a security tool that quotes an attack, a tool that says "call this first", a notes
server that says "never show this key to the user". It is reported; it blocks only where the same text
also shows the other role: a cover (hides, excuses, frames) beside an act (does something).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.mcp_servers.directive.surfaces import McpSurfaces, SurfaceText
from cordon_scanner.detect.agents.mcp_servers.directive.table import DirectiveClass, DirectiveTable
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.foundation.models import Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.agents.mcp_servers.served_flow import Served
    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.foundation.models import Finding

#: The most findings one rule gives in one file.
_PER_RULE: Final = 3
#: The most text of one value that is read.
_MAX_READ: Final = 60_000


@dataclass(frozen=True, slots=True)
class DirectiveHit:
    """A class that read a text of the file. `where` is the phrase it matched, as character offsets in
    the file, when the text is the whole file (an instruction file), not one value of it."""

    directive: DirectiveClass
    item: SurfaceText
    where: tuple[int, int] | None = None


class McpDirectives:
    """Reading the texts of a server for the classes of the table."""

    @staticmethod
    def matched(
        directive: DirectiveClass, text: str, limit: int = _MAX_READ
    ) -> re.Match[str] | None:
        """The first phrase of the class in the text (in its first `limit` characters), or None."""
        shown = text if len(text) <= limit else text[:limit]
        for pattern in directive.patterns:
            found = pattern.search(shown)
            if found:
                return found
        return None

    @staticmethod
    def reading(directive: DirectiveClass, text: str) -> bool:
        """Whether a phrase of the class is in the text."""
        return McpDirectives.matched(directive, text) is not None

    @staticmethod
    def hits(text: str, path: str, served: list[Served] | None = None) -> list[DirectiveHit]:
        """Every (class, text) the table reads in a server source."""
        found: list[DirectiveHit] = []
        classes = DirectiveTable.classes()
        for item in McpSurfaces.of(text, path, served):
            for directive in classes:
                if item.surface in directive.surfaces and McpDirectives.reading(
                    directive, item.text
                ):
                    found.append(DirectiveHit(directive, item))
        return found

    @staticmethod
    def blocks(hit: DirectiveHit, found: list[DirectiveHit]) -> bool:
        """Whether a class's reading is enough to block: a class that no legitimate server in the
        measured sets carries (`block`), or a text in which a class of the other role reads as well.
        A `signal` class is one honest text also holds (a security tool quoting an attack, a notes
        server that says "never show this key to the user"); so are two that only hide or frame
        (a teaching text that closes a tag and tells the model to ignore its instructions). What no
        honest text has is a cover and an act together: hiding it and doing it."""
        if hit.directive.strength == "block":
            return True
        roles = {other.directive.role for other in found if other.item == hit.item}
        return {"cover", "act"} <= roles

    @classmethod
    def findings(
        cls, unit: FileUnit, ctx: ScanContext, text: str, served: list[Served] | None = None
    ) -> Iterator[Finding]:
        """One finding for each (class, surface) text read, at most three to a rule."""
        found = cls.hits(text, unit.content.path, served)
        if not found:
            return
        count: dict[str, int] = {}
        for hit in found:
            rule = DirectiveTable.rule_id(hit.item.surface, hit.directive.id)
            if count.get(rule, 0) >= _PER_RULE:
                continue
            count[rule] = count.get(rule, 0) + 1
            yield cls.finding(rule, unit, ctx, text, hit, cls.blocks(hit, found))

    @classmethod
    def _phrase(cls, text: str, hit: DirectiveHit) -> tuple[int, int] | None:
        """Where the matched phrase itself is in the file, when it is written there as it was read: the line a person
        opens is the line of the phrase, not the first line of a long text. None when the text was assembled or
        decoded and the phrase is not in the file as it is."""
        match = cls.matched(hit.directive, hit.item.text)
        if match is None or not match.group(0):
            return None
        phrase = match.group(0)
        at = text.find(phrase, hit.item.start, hit.item.end)
        return (at, at + len(phrase)) if at >= 0 else None

    @classmethod
    def finding(
        cls,
        rule: str,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        hit: DirectiveHit,
        conclusive: bool,
        note: str = " One text like this is not conclusive, so it is reported for review.",
    ) -> Finding:
        begin, finish = hit.where or cls._phrase(text, hit) or (hit.item.start, hit.item.end)
        start = AgentFinding.byte_at(unit, text, begin)
        end = AgentFinding.byte_at(unit, text, finish)
        note = "" if conclusive else note
        return AgentFinding.finding(
            rule,
            unit,
            ctx,
            start,
            end,
            message=RULES[rule].message + note,
            severity=None if conclusive else Severity.MEDIUM,
            basis=(
                "directive",
                hit.item.surface,
                f"class:{hit.directive.id}",
                f"strength:{hit.directive.strength}",
                *(f"via:{v}" for v in hit.item.via),
            ),
        )


__all__ = ["DirectiveHit", "McpDirectives"]
