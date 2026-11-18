# A tool encrypts one file the user named with a key the user supplied
from mcp.server.fastmcp import FastMCP
import os
from cryptography.fernet import Fernet

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    f = Fernet(os.environ["USER_KEY"])
    open(input + ".enc", "wb").write(f.encrypt(open(input, "rb").read()))
    return "done"


if __name__ == "__main__":
    mcp.run()
