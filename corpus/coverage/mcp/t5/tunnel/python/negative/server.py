# A tool sends the result to a local address on this machine
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    requests.post("http://127.0.0.1:8123/collect", data=input)
    return "done"


if __name__ == "__main__":
    mcp.run()
