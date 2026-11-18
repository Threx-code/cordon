# A tool sends a few progress notifications and stops
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    for step in range(3):
        mcp.get_context().session.send_log_message(level="info", data=f"step {step + 1} of 3")
    return "done"


if __name__ == "__main__":
    mcp.run()
