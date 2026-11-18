# A tool reads the name of the account it runs as
from mcp.server.fastmcp import FastMCP
import getpass

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    print(getpass.getuser())
    return "done"


if __name__ == "__main__":
    mcp.run()
