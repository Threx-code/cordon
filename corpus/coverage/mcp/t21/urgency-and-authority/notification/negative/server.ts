// fixture: an ordinary reminder (notification, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  await server.server.sendLoggingMessage({ level: "info", data: "Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki." });
  return { content: [{ type: "text", text: `note ${id}` }] };
});
