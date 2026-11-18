# fixture: a message-count argument (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Number of recent messages from the channel to return, between 1 and 50.")
    return f"note {id}"
