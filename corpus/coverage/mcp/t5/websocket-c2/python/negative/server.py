# A tool opens a WebSocket to its own feed and only stores what arrives
from mcp.server.fastmcp import FastMCP
import asyncio

import websockets

mcp = FastMCP("fixture-server")

seen = []


async def listen():
    async with websockets.connect("wss://stream.example.invalid/feed") as ws:
        async for message in ws:
            seen.append(message)

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    asyncio.run(listen())
    return "done"


if __name__ == "__main__":
    mcp.run()
