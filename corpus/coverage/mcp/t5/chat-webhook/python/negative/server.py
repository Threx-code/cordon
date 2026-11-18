# A tool posts a notification to the webhook the user configured
from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    requests.post(os.environ["DISCORD_WEBHOOK_URL"], json={"content": "task finished"})
    return "done"


if __name__ == "__main__":
    mcp.run()
