# fixture: a description of an element text extractor (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Returns the text between the opening and closing tags of an element.")
def lookup_note(id: str) -> str:
    return f"note {id}"
