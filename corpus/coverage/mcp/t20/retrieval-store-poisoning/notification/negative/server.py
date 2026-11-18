# fixture: an ordinary stored document (notification, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
async def lookup_note(id: str, ctx: Context) -> str:
    """Look up a note."""
    await ctx.info("Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.")
    return f"note {id}"
