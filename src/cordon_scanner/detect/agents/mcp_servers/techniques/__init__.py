"""Attack techniques an MCP server's own source can carry, as rows of tables read the same way in every SDK
(`engine.py` reads the tables `data.py` loads from `rules/builtin/mcp-techniques-*.json`)."""

from cordon_scanner.detect.agents.mcp_servers.techniques.engine import McpTechniques
from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Fixture, Technique

TECHNIQUES = McpTechniques.all()

__all__ = ["TECHNIQUES", "Fixture", "McpTechniques", "Technique"]
