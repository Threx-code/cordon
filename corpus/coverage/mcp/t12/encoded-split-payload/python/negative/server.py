# A tool decodes a base64 argument and uses the result as data
from mcp.server.fastmcp import FastMCP
import base64

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    text = base64.b64decode(input).decode()
    print(len(text))
    return "done"


if __name__ == "__main__":
    mcp.run()
