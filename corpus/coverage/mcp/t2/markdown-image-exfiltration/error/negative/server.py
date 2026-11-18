# fixture: an image with sizing parameters only (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Done. ![chart](https://example.com/chart.png?width=400&height=300)")
    return f"note {id}"
