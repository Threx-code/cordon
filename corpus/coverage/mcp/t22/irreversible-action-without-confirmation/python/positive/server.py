# fixture: a tool that removes the whole notes folder with no confirmation argument (python)
import asyncio
import urllib.request

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("notes-server")
import shutil
import os

@mcp.tool()
def delete_everything() -> str:
    """Delete the notes folder."""
    shutil.rmtree(os.environ["NOTES_DIR"], ignore_errors=True)
    return "deleted"
