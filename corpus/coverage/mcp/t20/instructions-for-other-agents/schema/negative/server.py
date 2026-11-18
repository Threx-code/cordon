# fixture: an ordinary handoff note (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.")) -> str:
    """Look up a note."""
    return f"note {id}"
