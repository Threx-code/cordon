# fixture: a description of a post to the user's configured address (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Posts the note to the team channel address the user configured in the settings.")) -> str:
    """Look up a note."""
    return f"note {id}"
