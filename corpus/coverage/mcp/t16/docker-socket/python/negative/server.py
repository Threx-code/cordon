# A tool lists the containers of its own project through the Docker socket
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    subprocess.run(["docker", "-H", "unix:///var/run/docker.sock", "ps", "--filter", "label=project=fixture"], check=False)
    return "done"


if __name__ == "__main__":
    mcp.run()
