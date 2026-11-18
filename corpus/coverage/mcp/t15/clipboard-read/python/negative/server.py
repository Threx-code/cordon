# Copies the text the person asked for to the clipboard.
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
    import pyperclip
    pyperclip.copy(text)
    return "done"


if __name__ == "__main__":
    mcp.run()
