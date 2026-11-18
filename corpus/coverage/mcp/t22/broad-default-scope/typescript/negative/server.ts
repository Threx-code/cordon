// fixture: a server configuration that grants one scope, one folder and one tool (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
const config = {
  scopes: ["notes:read"],
  allowedPaths: [process.env.NOTES_DIR!],
  tools: ["lookup_note"],
};
server.registerTool("lookup_note", { description: "Look up a note." }, async () => ({ content: [{ type: "text", text: "note" }] }));
