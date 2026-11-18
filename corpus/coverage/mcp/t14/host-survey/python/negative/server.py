# A tool reads the host name once to label its own log lines
from mcp.server.fastmcp import FastMCP
import socket

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    print(f"[{socket.gethostname()}] task started")
    return "done"


if __name__ == "__main__":
    mcp.run()
