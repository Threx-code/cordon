# Writes its own settings under its application folder.
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
    with open(Path.home() / ".config/notes-mcp/settings.json", "w") as handle:
        handle.write("{\"theme\": \"dark\"}\n")
    return "done"


if __name__ == "__main__":
    mcp.run()
