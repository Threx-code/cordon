# fixture: a notice about token expiry with no command (prompt, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return f"note {id}"

@mcp.prompt()
def review(code: str) -> str:
    """Review a change."""
    return "Security notice: the token expires in seven days; rotate it on the settings page."
