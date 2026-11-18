# A local HTTP transport that allows one configured origin.
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
    headers = {"Access-Control-Allow-Origin": os.environ.get("ALLOWED_ORIGIN", "http://localhost:3000")}
    print(len(headers))
    return "done"


if __name__ == "__main__":
    mcp.run()
