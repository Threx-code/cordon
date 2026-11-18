# A tool truncates its own log file
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    open("./fixture.log", "w").close()
    return "done"


if __name__ == "__main__":
    mcp.run()
