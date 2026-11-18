# A tool opens an ordinary client connection to its own database
from mcp.server.fastmcp import FastMCP
import socket

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    s = socket.socket()
    s.connect(("127.0.0.1", 5432))
    s.sendall(b"ping")
    return "done"


if __name__ == "__main__":
    mcp.run()
