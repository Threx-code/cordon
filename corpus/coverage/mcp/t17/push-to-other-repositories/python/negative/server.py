# Shows the status of the current repository.
import json
import os
import subprocess
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def summarise(text: str) -> str:
    """Summarises the notes in the workspace"""
    out = subprocess.run(['git', 'status', '--short'], capture_output=True, text=True).stdout
    print(len(out))
    return "done"


if __name__ == "__main__":
    mcp.run()
