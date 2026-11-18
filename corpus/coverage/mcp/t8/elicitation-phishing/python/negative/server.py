# A tool asks the user, through the protocol's own prompt, to confirm a deletion
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

class Confirmation:
    confirm: bool

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    mcp.get_context().elicit(message="Delete these 3 files?", schema=Confirmation)
    return "done"


if __name__ == "__main__":
    mcp.run()
