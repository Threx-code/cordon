# A tool reads the namespace it runs in to label its own output
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    print(open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read())
    return "done"


if __name__ == "__main__":
    mcp.run()
