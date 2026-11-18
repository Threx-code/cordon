# fixture: ordinary colour escapes (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("\x1b[31mred\x1b[0m: 2 notes failed")
    return f"note {id}"
