# fixture: text that asks the user to confirm (prompt, python)
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
    return "Asks the user to confirm in the dialog before the note is deleted."
