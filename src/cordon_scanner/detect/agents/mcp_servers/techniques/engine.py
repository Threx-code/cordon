"""Attack techniques an MCP server's own source can carry, read the same way in every SDK.

A tool server is ordinary code: it can open a reverse shell, download and run what it fetched, hide a payload in
character codes or carry data out through a DNS name. The server is written in whichever SDK its author chose
(TypeScript or JavaScript, Python, Go, Rust, Java, C#), and the technique is the same in each, so each one is a row
here: the shapes it takes in source text, what else must be there for it to be that and not something harmless, and
the inert fixtures that say what is and is not an instance.

```
  Technique(rule_id, family, patterns, requires, unless, at_least, severity, positive, negative)
      patterns   shapes of the technique in source, in any language; `at_least` of them must match
      requires   shapes that must also be in the file (the socket a shell is attached to)
      unless     shapes that make it something else (a guard, a test)
```

Only files that build an MCP server are read (`McpServerFindings`), so a security tool that quotes these shapes in
a signature file, or a build script, is not one. Every pattern is bounded: no nested or open-ended repetition.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.agents.mcp_servers.techniques.data import TechniqueData
from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Fixture, Technique
from cordon_scanner.foundation.limits import WHOLE_FILE_BYTES
from cordon_scanner.foundation.models import Category


class McpTechniques:
    """`scan(text)`: every technique in a source file; `rules(factory, references)`: their catalogue entries."""

    FAMILIES: ClassVar[tuple[str, ...]] = (
        "T3",
        "T5",
        "T6",
        "T7",
        "T8",
        "T12",
        "T13",
        "T14",
        "T16",
        "T18",
        "T19",
    )
    _all: ClassVar[tuple[Technique, ...] | None] = None

    @classmethod
    def all(cls) -> tuple[Technique, ...]:
        """Every row of every table."""
        if cls._all is None:
            cls._all = TechniqueData.load()
        return cls._all

    @classmethod
    def scan(cls, text: str) -> Iterator[tuple[Technique, int, int]]:
        """(technique, start, end) of each technique found in `text`."""
        if len(text) > WHOLE_FILE_BYTES:
            return
        for technique in cls.all():
            span = technique.find(text)
            if span is not None:
                yield technique, span[0], span[1]

    @classmethod
    def rules(cls, factory: Callable[..., Any], references: tuple[str, ...]) -> dict[str, Any]:
        """The catalogue entry of every technique, built with the caller's rule factory."""
        return {
            t.rule_id: factory(
                t.rule_id,
                t.title,
                Category.SUSPICIOUS,
                t.severity,
                t.confidence,
                t.message,
                t.remediation,
                references,
            )
            for t in cls.all()
        }


__all__ = ["Fixture", "McpTechniques", "Technique"]
