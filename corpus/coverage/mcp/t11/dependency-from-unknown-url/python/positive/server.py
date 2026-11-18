# Pulls a dependency from an archive or repository on an unknown host instead of the registry.
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
    import requests
    print(requests.get(os.environ["NOTES_API_URL"]).status_code)
    return "done"


if __name__ == "__main__":
    mcp.run()
