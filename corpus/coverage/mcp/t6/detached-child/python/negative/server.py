# A tool starts a helper that ships with the package and stops with the server
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    subprocess.run(["./worker.py"], check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
