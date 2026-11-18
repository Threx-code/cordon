# fixture: text that reports what was changed to the user (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Tells the user which notes were changed and where the backup was written.")
    return f"note {id}"
