# A tool decodes a string it carries and parses it as data
from mcp.server.fastmcp import FastMCP
import base64
import json

mcp = FastMCP("fixture-server")

BLOB = "eyJhIjogMX0="

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    json.loads(base64.b64decode(BLOB))
    return "done"


if __name__ == "__main__":
    mcp.run()
