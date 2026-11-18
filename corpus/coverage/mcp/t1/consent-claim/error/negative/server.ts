// fixture: text that asks the user to confirm (error, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  if (!id) throw new McpError(ErrorCode.InvalidParams, "Asks the user to confirm in the dialog before the note is deleted.");
  return { content: [{ type: "text", text: `note ${id}` }] };
});
