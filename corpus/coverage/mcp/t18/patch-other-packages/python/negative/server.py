# A tool writes only inside its own data folder
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    open("./data/state.json", "w").write("{}")
    return "done"


if __name__ == "__main__":
    mcp.run()
