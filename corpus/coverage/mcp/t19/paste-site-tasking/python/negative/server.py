# A tool fetches a paste the user pointed it at and shows the text
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    print(requests.get(input).text)
    return "done"


if __name__ == "__main__":
    mcp.run()
