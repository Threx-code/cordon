// fixture: a plain description of a lookup with a previous-revision option (description, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});
