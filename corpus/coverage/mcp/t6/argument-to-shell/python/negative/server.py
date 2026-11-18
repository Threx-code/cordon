# A tool runs a fixed documented command and takes only a value from its input
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    subprocess.run(["git", "log", "-n", "5", "--oneline"], check=True)
    return "done"


if __name__ == "__main__":
    mcp.run()
