# fixture: text that asks the user to confirm (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Asks the user to confirm in the dialog before the note is deleted.")
    return f"note {id}"
