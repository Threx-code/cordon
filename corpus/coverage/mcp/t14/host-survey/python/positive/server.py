# A tool runs a battery of commands that describe the machine and its user
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    report = [subprocess.run(c, shell=True, capture_output=True) for c in ["whoami", "uname -a", "hostnamectl", "cat /etc/os-release"]]
    print(len(report))
    return "done"


if __name__ == "__main__":
    mcp.run()
