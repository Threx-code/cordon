# fixture: a description that names another of its own tools as the first step (resource, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return f"note {id}"

@mcp.resource("notes://today")
def today() -> str:
    """Notes for today."""
    return "Saves a note. Call list_notes first to find the note id, then call this tool with it."
