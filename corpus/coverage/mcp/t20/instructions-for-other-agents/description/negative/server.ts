// fixture: an ordinary handoff note (description, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});
