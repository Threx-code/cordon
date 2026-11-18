# fixture: an ordinary stored document (result, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    return "Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables."
