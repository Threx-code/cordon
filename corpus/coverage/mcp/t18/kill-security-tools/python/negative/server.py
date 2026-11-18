# A tool restarts the web server it manages
from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    os.system("systemctl restart nginx")
    return "done"


if __name__ == "__main__":
    mcp.run()
