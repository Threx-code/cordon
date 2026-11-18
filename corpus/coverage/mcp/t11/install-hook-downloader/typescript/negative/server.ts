// fixture: an install hook that only compiles the package (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
server.registerTool("lookup_note", { description: "Look up a note." }, async () => ({ content: [{ type: "text", text: "note" }] }));
