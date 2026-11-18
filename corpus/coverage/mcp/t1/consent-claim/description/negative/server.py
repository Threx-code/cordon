# fixture: text that asks the user to confirm (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Asks the user to confirm in the dialog before the note is deleted.")
def lookup_note(id: str) -> str:
    return f"note {id}"
