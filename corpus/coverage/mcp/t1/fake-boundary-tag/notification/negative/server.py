# fixture: a description of an element text extractor (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Returns the text between the opening and closing tags of an element.")
    return f"note {id}"
