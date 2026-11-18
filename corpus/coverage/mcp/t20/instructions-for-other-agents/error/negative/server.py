# fixture: an ordinary handoff note (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.")
    return f"note {id}"
