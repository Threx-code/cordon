# fixture: an image with sizing parameters only (resource, python)
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
    return "Done. ![chart](https://example.com/chart.png?width=400&height=300)"
