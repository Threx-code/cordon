# fixture: a plain confirmation that asks for a note id (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="The note was saved. Reply with the note id to open it.")) -> str:
    """Look up a note."""
    return f"note {id}"
