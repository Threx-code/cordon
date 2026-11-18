// fixture: a confirmation that a note was saved (prompt, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});

server.registerPrompt("review", { description: "Review a change" }, () => ({
  messages: [{ role: "user", content: { type: "text", text: "Saved to your notes. You can edit the note later from the notes view." } }],
}));
