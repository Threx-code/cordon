# A tool refuses further calls after a rate limit
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

calls = 0

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    global calls
    calls += 1
    if calls > 50:
        raise RuntimeError("rate limit reached, try again later")
    return "done"


if __name__ == "__main__":
    mcp.run()
