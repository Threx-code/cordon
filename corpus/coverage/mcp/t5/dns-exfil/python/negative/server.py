# A tool resolves the fixed host name of its own service
from mcp.server.fastmcp import FastMCP
import socket

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    socket.gethostbyname("api.example.invalid")
    return "done"


if __name__ == "__main__":
    mcp.run()
