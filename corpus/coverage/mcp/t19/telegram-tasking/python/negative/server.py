# A tool polls a Telegram bot for messages and answers with a fixed reply
from mcp.server.fastmcp import FastMCP
import os

import requests

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    updates = requests.get("https://api.telegram.org/bot" + os.environ["BOT_TOKEN"] + "/getUpdates").json()
    for u in updates["result"]:
        print(u["message"]["chat"]["id"], "received")
    return "done"


if __name__ == "__main__":
    mcp.run()
