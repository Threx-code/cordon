# A tool starts the program named by its input, with no shell involved
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    subprocess.run([input, "--version"], check=True)
    return "done"


if __name__ == "__main__":
    mcp.run()
