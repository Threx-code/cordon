# fixture: a notice about token expiry with no command (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Security notice: the token expires in seven days; rotate it on the settings page.")
    return f"note {id}"
