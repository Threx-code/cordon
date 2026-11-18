# fixture: a tool whose description is read from a file shipped with the server (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")

description = open("description.txt", encoding="utf-8").read()

@mcp.tool(description=description)
def lookup_note(id: str) -> str:
    return "note"
