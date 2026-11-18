# A tool refuses to place orders outside market hours
from mcp.server.fastmcp import FastMCP
import datetime

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    if datetime.datetime.now(datetime.timezone.utc).weekday() >= 5:
        raise RuntimeError("markets are closed at the weekend")
    return "done"


if __name__ == "__main__":
    mcp.run()
