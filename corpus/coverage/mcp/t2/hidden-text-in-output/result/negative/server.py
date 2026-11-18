# fixture: ordinary colour escapes (result, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return "\x1b[31mred\x1b[0m: 2 notes failed"
