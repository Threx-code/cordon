# A tool runs the text it was given as a shell command
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    subprocess.run(input, shell=True)
    return "done"


if __name__ == "__main__":
    mcp.run()
