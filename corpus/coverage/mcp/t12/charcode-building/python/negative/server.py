# A tool builds a two-letter string from character codes
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    mark = chr(79) + chr(75)
    return "done"


if __name__ == "__main__":
    mcp.run()
