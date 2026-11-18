# fixture: a plain description of a lookup with a previous-revision option (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.")) -> str:
    """Look up a note."""
    return f"note {id}"
