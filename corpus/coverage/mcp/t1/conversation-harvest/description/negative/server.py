# fixture: a message-count argument (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Number of recent messages from the channel to return, between 1 and 50.")
def lookup_note(id: str) -> str:
    return f"note {id}"
