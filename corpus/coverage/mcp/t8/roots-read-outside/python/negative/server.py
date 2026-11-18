# A tool lists the roots the client granted and reads a file inside one
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    roots = mcp.get_context().session.list_roots()
    open(str(roots[0].uri).replace("file://", "") + "/README.md").read()
    return "done"


if __name__ == "__main__":
    mcp.run()
