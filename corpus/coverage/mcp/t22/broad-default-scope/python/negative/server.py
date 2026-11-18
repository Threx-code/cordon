# fixture: a server configuration that grants one scope, one folder and one tool (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

CONFIG = {
    "scopes": ["notes:read"],
    "allowed_paths": ["/srv/notes"],
    "tools": ["lookup_note"],
}
