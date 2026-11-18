"""Attack techniques an MCP server's own source can carry, as rows of tables read the same way in every SDK
(`engine.py` reads the tables of `table_core.py`, `table_extra.py` and `table_persist.py`)."""

from cordon_scanner.detect.agents.mcp_servers.techniques.engine import McpTechniques
from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Fixture, Technique

TECHNIQUES = McpTechniques.all()

__all__ = ["TECHNIQUES", "Fixture", "McpTechniques", "Technique"]
