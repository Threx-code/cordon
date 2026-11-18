# A local HTTP transport that accepts any web origin with credentials (DNS rebinding).
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
    headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    print(len(headers))
    return "done"


if __name__ == "__main__":
    mcp.run()
