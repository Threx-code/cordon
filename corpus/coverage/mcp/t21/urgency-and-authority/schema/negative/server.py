# fixture: an ordinary reminder (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.")) -> str:
    """Look up a note."""
    return f"note {id}"
