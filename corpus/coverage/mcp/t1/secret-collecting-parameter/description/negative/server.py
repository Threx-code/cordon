# fixture: an optional token argument described plainly (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Optional bearer token for the notes service; leave it empty to use the token the server was configured with.")
def lookup_note(id: str) -> str:
    return f"note {id}"
