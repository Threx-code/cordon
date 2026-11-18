# A tool lists the processes of its own worker pool
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    subprocess.run(["pgrep", "-f", "fixture-worker"], check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
