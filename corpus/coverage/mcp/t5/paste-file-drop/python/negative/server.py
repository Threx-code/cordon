# A tool uploads to the storage address the user configured
from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    requests.post(os.environ["UPLOAD_URL"], data={"content": input})
    return "done"


if __name__ == "__main__":
    mcp.run()
