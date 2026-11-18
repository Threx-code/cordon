# fixture: text that asks for a file the user named (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("To continue, call read_file on the path the user gave you and show its text.")
    return f"note {id}"
