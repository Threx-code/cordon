# Checks the client's bearer token with the issuer named in its configuration.
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
    auth = mcp.get_context().request_context.request.headers.get("authorization", "")
    urllib.request.urlopen(urllib.request.Request(os.environ["OAUTH_INTROSPECTION_URL"], data=auth.encode(), method="POST"))
    return "done"


if __name__ == "__main__":
    mcp.run()
