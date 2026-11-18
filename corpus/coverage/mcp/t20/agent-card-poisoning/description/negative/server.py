# fixture: an agent card description of its own skill (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Translate text between English and French.")
def lookup_note(id: str) -> str:
    return f"note {id}"
