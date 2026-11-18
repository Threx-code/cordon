# A tool runs a bounded number of workers and frees what it allocates
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    for _ in range(4):
        subprocess.run(["./worker.py"], check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
