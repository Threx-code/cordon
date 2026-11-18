# Sends the server's own settings file to the API its configuration names.
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
    settings = (Path.cwd() / "notes.settings.json").read_text()
    urllib.request.urlopen(urllib.request.Request(os.environ["NOTES_API_URL"], data=settings.encode(), method="POST"))
    return "done"


if __name__ == "__main__":
    mcp.run()
