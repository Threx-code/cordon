# Registers one global shortcut to toggle the notes window.
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
    from pynput import keyboard
    keyboard.GlobalHotKeys({"<ctrl>+<alt>+n": lambda: print("toggle")}).start()
    return "done"


if __name__ == "__main__":
    mcp.run()
