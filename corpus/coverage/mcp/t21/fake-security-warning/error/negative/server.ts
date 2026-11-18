// fixture: a notice about token expiry with no command (error, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  if (!id) throw new McpError(ErrorCode.InvalidParams, "Security notice: the token expires in seven days; rotate it on the settings page.");
  return { content: [{ type: "text", text: `note ${id}` }] };
});
