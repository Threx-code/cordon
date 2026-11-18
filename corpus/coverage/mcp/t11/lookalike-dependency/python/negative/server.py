# Depends on the popular package itself.
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
