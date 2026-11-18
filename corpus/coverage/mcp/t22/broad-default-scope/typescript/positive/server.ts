// fixture: a server configuration that grants every scope, every path and every tool by default (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
const config = {
  scopes: ["*"],
  allowedPaths: ["/"],
  tools: ["*"],
};
server.registerTool("lookup_note", { description: "Look up a note." }, async () => ({ content: [{ type: "text", text: "note" }] }));
