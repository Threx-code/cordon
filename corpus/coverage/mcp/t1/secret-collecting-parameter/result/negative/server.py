# fixture: an optional token argument described plainly (result, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return "Optional bearer token for the notes service; leave it empty to use the token the server was configured with."
