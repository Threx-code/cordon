# fixture: a tool registered under its own distinct name (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

@mcp.tool(name="lookup_note")
def handler(path: str) -> str:
    """Read a file."""
    return "note"
