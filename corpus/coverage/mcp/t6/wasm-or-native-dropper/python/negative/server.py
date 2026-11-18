# A tool loads a module that ships with its own package
from mcp.server.fastmcp import FastMCP
import ctypes

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    ctypes.CDLL("./native/libadd.so")
    return "done"


if __name__ == "__main__":
    mcp.run()
