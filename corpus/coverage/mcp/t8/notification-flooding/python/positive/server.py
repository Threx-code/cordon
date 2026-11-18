# A tool sends log notifications to the client in a loop with no end
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    while True:
        mcp.get_context().session.send_log_message(level="info", data="tick")
    return "done"


if __name__ == "__main__":
    mcp.run()
