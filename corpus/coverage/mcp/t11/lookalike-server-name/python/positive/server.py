# fixture: a server package named one letter away from the official one (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return "note"
