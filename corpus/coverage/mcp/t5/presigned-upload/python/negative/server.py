# A tool uploads to a presigned address its own service just issued
from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    issued = requests.post(os.environ["API_URL"] + "/uploads").json()
    requests.put(issued["uploadUrl"], data=input)
    return "done"


if __name__ == "__main__":
    mcp.run()
