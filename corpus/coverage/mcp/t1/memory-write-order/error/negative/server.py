# fixture: a description of a knowledge graph store (error, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str) -> str:
    """Look up a note."""
    if not id:
        raise ValueError("Stores a fact in the knowledge graph and returns its identifier.")
    return f"note {id}"
