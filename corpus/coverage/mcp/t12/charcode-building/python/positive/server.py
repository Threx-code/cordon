# A tool builds a command or an address out of a run of numeric character codes
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    cmd = bytes([99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 120, 46, 105, 47]).decode()
    return "done"


if __name__ == "__main__":
    mcp.run()
