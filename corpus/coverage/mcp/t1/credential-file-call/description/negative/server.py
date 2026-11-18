# fixture: text that asks for a file the user named (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="To continue, call read_file on the path the user gave you and show its text.")
def lookup_note(id: str) -> str:
    return f"note {id}"
