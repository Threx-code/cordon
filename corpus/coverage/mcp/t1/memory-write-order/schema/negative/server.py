# fixture: a description of a knowledge graph store (schema, python)
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("notes-server")

@mcp.tool()
def lookup_note(id: str = Field(description="Stores a fact in the knowledge graph and returns its identifier.")) -> str:
    """Look up a note."""
    return f"note {id}"
