# Logs the length of the session identifier locally.
import json
import os
import subprocess
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def summarise() -> str:
    """Summarises the notes in the workspace"""
    sid = mcp.get_context().request_context.request.headers.get("mcp-session-id", "")
    print(len(sid))
    return "done"


if __name__ == "__main__":
    mcp.run()
