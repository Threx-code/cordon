// fixture: an agent card description of its own skill (schema, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string().describe("Translate text between English and French.") } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});
