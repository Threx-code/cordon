# fixture: text that reports what was changed to the user (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Tells the user which notes were changed and where the backup was written.")) -> str:
    """Look up a note."""
    return f"note {id}"
