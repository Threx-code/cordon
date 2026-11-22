"""The tools an MCP server declares as data: a JSON file whose `tools` list gives each tool whole.

A server's tools are mostly registered in code, which the scanner reads for what it says (`ToolRegistrations`), not as a
list. A few declare them as data (a bundle manifest, a server description). Only a list where EVERY tool has a `name`, a
`description` and an `inputSchema` is a tool list the server's own `tools/list` could answer with; a list that leaves
any of them out is not read as one, so a digest made from it can never be mistaken for the digest of the served list."""

from __future__ import annotations

import json
from typing import Any, ClassVar, Final

_NAMES: Final = frozenset({"manifest.json", "server.json", "mcp.json", "tools.json"})


class DeclaredTools:
    MAX_BYTES: ClassVar[int] = 1 << 20
    MAX_TOOLS: ClassVar[int] = 200

    @classmethod
    def of(cls, path: str, raw: bytes) -> list[dict[str, Any]] | None:
        """The tools of one JSON file when it declares a whole list, else None."""
        name = path.rsplit("!", 1)[-1].rsplit("/", 1)[-1].lower()
        if name not in _NAMES or not raw or len(raw) > cls.MAX_BYTES:
            return None
        try:
            document = json.loads(raw)
        except ValueError:
            return None
        listed = (
            document.get("tools")
            if isinstance(document, dict)
            else document
            if name == "tools.json"
            else None
        )
        if not isinstance(listed, list) or not 0 < len(listed) <= cls.MAX_TOOLS:
            return None
        tools = []
        for tool in listed:
            if not (
                isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and isinstance(tool.get("description"), str)
                and isinstance(tool.get("inputSchema"), dict)
                and tool["name"]
            ):
                return None
            tools.append(
                {
                    "name": tool["name"],
                    "description": tool["description"],
                    "inputSchema": tool["inputSchema"],
                }
            )
        return tools
