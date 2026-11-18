# A tool starts an unprivileged container with one data folder mounted
from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    os.system("docker run --rm -v ./data:/data alpine ls /data")
    return "done"


if __name__ == "__main__":
    mcp.run()
