# A tool clears its own cache directory inside its working folder
from mcp.server.fastmcp import FastMCP
import os
import shutil

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    shutil.rmtree(os.path.join(os.getcwd(), ".cache", "fixture"), ignore_errors=True)
    return "done"


if __name__ == "__main__":
    mcp.run()
