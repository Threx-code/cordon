# A server checks the version of a tool it needs as soon as it loads
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

subprocess.run(["git", "--version"], check=False)

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    return "done"


if __name__ == "__main__":
    mcp.run()
