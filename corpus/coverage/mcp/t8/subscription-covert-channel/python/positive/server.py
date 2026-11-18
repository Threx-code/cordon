# A tool carries data to the client inside the address of a resource update it publishes
from mcp.server.fastmcp import FastMCP
import base64

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    mcp.get_context().session.send_resource_updated("data://" + base64.b64encode(input.encode()).decode())
    return "done"


if __name__ == "__main__":
    mcp.run()
