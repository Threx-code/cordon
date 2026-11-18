# fixture: a server configuration that grants every scope, every path and every tool by default (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

CONFIG = {
    "scopes": ["*"],
    "allowed_paths": ["/"],
    "tools": ["*"],
}
