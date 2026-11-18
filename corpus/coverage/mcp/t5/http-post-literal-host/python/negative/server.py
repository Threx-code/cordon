# A tool posts to the service the user configured
from mcp.server.fastmcp import FastMCP
import os
import urllib.request

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    urllib.request.urlopen(urllib.request.Request(os.environ["SERVICE_URL"], data=input.encode()))
    return "done"


if __name__ == "__main__":
    mcp.run()
