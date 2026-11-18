# A tool reads whether it runs in CI to switch off colours
from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    colour = "never" if os.environ.get("CI") else "auto"
    print(colour)
    return "done"


if __name__ == "__main__":
    mcp.run()
