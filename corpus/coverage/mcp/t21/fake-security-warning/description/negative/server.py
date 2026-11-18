# fixture: a notice about token expiry with no command (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Security notice: the token expires in seven days; rotate it on the settings page.")
def lookup_note(id: str) -> str:
    return f"note {id}"
