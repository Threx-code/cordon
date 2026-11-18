# fixture: a tool that uses the locale and host name to format dates and paths (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")
import locale
import socket

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return f"note written on {socket.gethostname()} ({locale.getlocale()[0]})"
