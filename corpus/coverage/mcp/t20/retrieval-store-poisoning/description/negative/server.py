# fixture: an ordinary stored document (description, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool(description="Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.")
def lookup_note(id: str) -> str:
    return f"note {id}"
