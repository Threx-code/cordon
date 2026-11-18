# fixture: a confirmation that a note was saved (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Saved to your notes. You can edit the note later from the notes view.")) -> str:
    """Look up a note."""
    return f"note {id}"
