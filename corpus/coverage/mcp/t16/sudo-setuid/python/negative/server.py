# A tool makes its own script executable for its owner
from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    os.chmod("./bin/run", 0o755)
    return "done"


if __name__ == "__main__":
    mcp.run()
