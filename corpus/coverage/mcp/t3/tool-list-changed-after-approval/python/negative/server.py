# fixture: a tool list that changes when the user enables a plugin (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")
@mcp.tool()
async def reload_plugins(ctx: Context) -> str:
    """Reload the plugins the user enabled."""
    load_enabled_plugins(mcp)
    await ctx.session.send_tool_list_changed()
    return "reloaded"
