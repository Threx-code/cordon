# fixture: a confirmation that a note was saved (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Saved to your notes. You can edit the note later from the notes view.")
    return f"note {id}"
