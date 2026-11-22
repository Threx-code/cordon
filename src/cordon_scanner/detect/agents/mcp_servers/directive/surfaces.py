"""Every text an MCP server hands the agent, by the surface it arrives on.

```
  description   a tool's own description, its docstring, a constant or positional description
  schema        the description of one argument: `.describe("...")`, `Field(description=...)`
  result        what a tool returns                       (followed through constants, joins, decoding)
  error         the message of what a handler raises, or of a result marked `isError`
  notification  a log or progress message sent through the request's context or session
  resource      the content a resource serves
  prompt        a prompt template's messages
```

The agent reads all seven as its own context, so an order written into any of them steers it. The
first two are read from the registration's text (`McpServerSource.described`); the other five from
the handler's code (`served_python.py`, `served_js.py`). `McpDirectives` reads each text for the
orders and tricks of its table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cordon_scanner.detect.agents.mcp_servers.directive.lexical import LexicalSurfaces
from cordon_scanner.detect.agents.mcp_servers.directive.table import SURFACES
from cordon_scanner.detect.agents.mcp_servers.served_flow import Served
from cordon_scanner.detect.agents.mcp_servers.served_text import ServedText
from cordon_scanner.detect.agents.mcp_servers.source import McpServerSource

#: The most texts one file gives.
_MAX_TEXTS: Final = 400


@dataclass(frozen=True, slots=True)
class SurfaceText:
    """One text and where it is: `start` and `end` are character offsets in the file."""

    surface: str
    text: str
    start: int
    end: int
    via: tuple[str, ...]


class McpSurfaces:
    @staticmethod
    def of(text: str, path: str, served: list[Served] | None = None) -> list[SurfaceText]:
        """The texts of a server source, once each per surface, in file order. Python and the
        JavaScript family give all seven surfaces, and so do Go (`lexical.py`); another language
        gives its descriptions."""
        found = [
            SurfaceText(surface, value, start, end, ("literal",))
            for surface, value, start, end in McpServerSource.described(text, path)
        ]
        found.extend(
            SurfaceText(item.kind, item.text, item.start, item.end, item.via)
            for item in (ServedText.served(text, path) if served is None else served)
        )
        found.extend(
            SurfaceText(item.kind, item.text, item.start, item.end, item.via)
            for item in LexicalSurfaces.of(text, path)
        )
        seen: set[tuple[str, str]] = set()
        out: list[SurfaceText] = []
        for item in sorted(found, key=lambda s: s.start):
            key = (item.surface, item.text)
            if key in seen or not item.text.strip():
                continue
            seen.add(key)
            out.append(item)
            if len(out) >= _MAX_TEXTS:
                break
        return out


__all__ = ["SURFACES", "McpSurfaces", "SurfaceText"]
