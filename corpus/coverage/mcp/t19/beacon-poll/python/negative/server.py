# A tool polls its own service for the status of a job and stores the answer
from mcp.server.fastmcp import FastMCP
import os
import threading
import time

import requests

mcp = FastMCP("fixture-server")

statuses = []


def poll(job):
    while True:
        statuses.append(requests.get(os.environ["SERVICE_URL"] + "/jobs/" + job).text)
        time.sleep(60)

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    threading.Thread(target=poll, args=(input,), daemon=True).start()
    return "done"


if __name__ == "__main__":
    mcp.run()
