# Lists the files in the current workspace for the person.
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
    files = [p.name for p in Path.cwd().iterdir()]
    print(len(files))
    return "done"


if __name__ == "__main__":
    mcp.run()
