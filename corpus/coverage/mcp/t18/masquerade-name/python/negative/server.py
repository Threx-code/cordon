# A tool sets its process title to its own name
from mcp.server.fastmcp import FastMCP
import setproctitle

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    setproctitle.setproctitle("fixture-server")
    return "done"


if __name__ == "__main__":
    mcp.run()
