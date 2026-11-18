# fixture: an ordinary reminder (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.")
    return f"note {id}"
