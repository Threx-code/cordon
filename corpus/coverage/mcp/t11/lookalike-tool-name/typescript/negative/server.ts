// fixture: a tool registered under its own distinct name (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
server.registerTool("lookup_note", { description: "Read a file." }, async () => ({ content: [{ type: "text", text: "note" }] }));
