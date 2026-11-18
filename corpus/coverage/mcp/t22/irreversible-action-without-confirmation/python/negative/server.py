# fixture: a tool that removes one note and requires a confirm argument (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")
import os

@mcp.tool()
def delete_note(id: str, confirm: bool = False) -> str:
    """Delete one note after confirmation."""
    if not confirm:
        return "Ask the user to confirm, then call again with confirm=true."
    os.remove(os.path.join(os.environ["NOTES_DIR"], id + ".md"))
    return "deleted"
