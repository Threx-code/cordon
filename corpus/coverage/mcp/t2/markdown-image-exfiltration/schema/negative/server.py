# fixture: an image with sizing parameters only (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Done. ![chart](https://example.com/chart.png?width=400&height=300)")) -> str:
    """Look up a note."""
    return f"note {id}"
