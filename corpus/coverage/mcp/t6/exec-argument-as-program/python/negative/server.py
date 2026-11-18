# A tool starts a fixed program and passes its input as one argument
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    subprocess.run(["grep", "-c", "--", input, "notes.txt"], check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
