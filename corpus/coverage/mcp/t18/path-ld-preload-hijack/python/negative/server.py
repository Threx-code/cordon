# A tool adds its own bin folder to the path of the programs it starts
from mcp.server.fastmcp import FastMCP
import os
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    subprocess.run(["tool"], env={**os.environ, "PATH": os.getcwd() + "/.venv/bin:" + os.environ["PATH"]}, check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
