# A tool downloads a file the user asked for and only saves it
from mcp.server.fastmcp import FastMCP
import urllib.request

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    urllib.request.urlretrieve("https://dl.example.invalid/report.pdf", "report.pdf")
    return "done"


if __name__ == "__main__":
    mcp.run()
