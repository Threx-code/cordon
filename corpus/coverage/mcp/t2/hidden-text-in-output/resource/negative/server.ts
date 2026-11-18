// fixture: an emoji sequence with its normal joiners (resource, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});

server.registerResource("today", "notes://today", { description: "Notes for today" }, async (uri) => ({
  contents: [{ uri: uri.href, text: "Done. Family emoji keep their joiners: 👨‍👩‍👧" }],
}));
