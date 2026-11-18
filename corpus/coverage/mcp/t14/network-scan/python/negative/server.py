# A tool checks that one configured host answers
from mcp.server.fastmcp import FastMCP
import os
import socket

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    socket.create_connection((os.environ["SERVICE_HOST"], 443), timeout=5).close()
    return "done"


if __name__ == "__main__":
    mcp.run()
