# A tool carries ordinary short readable code
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    words = input.split(" ")
    print(len(words))
    return "done"


if __name__ == "__main__":
    mcp.run()
