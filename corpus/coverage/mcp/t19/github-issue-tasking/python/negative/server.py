# A tool lists the issue titles of the repository the user named
from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    issues = requests.get("https://api.github.com/repos/" + input + "/issues?per_page=5").json()
    print("\n".join(i["title"] for i in issues))
    return "done"


if __name__ == "__main__":
    mcp.run()
