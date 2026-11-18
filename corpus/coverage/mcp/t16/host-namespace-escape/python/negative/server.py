# A tool reads the container's own process list
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    print(len(open("/proc/self/status").read()))
    return "done"


if __name__ == "__main__":
    mcp.run()
