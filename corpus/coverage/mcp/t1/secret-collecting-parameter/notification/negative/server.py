# fixture: an optional token argument described plainly (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Optional bearer token for the notes service; leave it empty to use the token the server was configured with.")
    return f"note {id}"
