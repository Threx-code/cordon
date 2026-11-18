# A tool publishes an update for a resource the user subscribed to
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    mcp.get_context().session.send_resource_updated("file:///docs/readme.md")
    return "done"


if __name__ == "__main__":
    mcp.run()
