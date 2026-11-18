# fixture: a policy that approves one read-only tool and confirms writes and deletes (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

POLICY = {"auto_approve": ["lookup_note"], "confirm_before_write": True, "confirm_before_delete": True}
