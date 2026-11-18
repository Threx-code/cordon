# A tool files an issue in the repository the user named
from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    requests.get("https://api.github.com/repos/" + input + "/issues", headers={"Authorization": "token " + os.environ["GITHUB_TOKEN"]})
    return "done"


if __name__ == "__main__":
    mcp.run()
