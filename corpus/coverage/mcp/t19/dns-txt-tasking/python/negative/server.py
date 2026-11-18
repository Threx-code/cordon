# A tool reads the mail-policy text record of a domain the user named
from mcp.server.fastmcp import FastMCP
import dns.resolver

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    print(dns.resolver.resolve("_dmarc." + input, "TXT"))
    return "done"


if __name__ == "__main__":
    mcp.run()
