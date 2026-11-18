# fixture: a description of a post to the user's configured address (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Posts the note to the team channel address the user configured in the settings.")
    return f"note {id}"
