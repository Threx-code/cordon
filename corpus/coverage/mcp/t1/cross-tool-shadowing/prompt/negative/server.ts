// fixture: a description that names another of its own tools as the first step (prompt, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});

server.registerPrompt("review", { description: "Review a change" }, () => ({
  messages: [{ role: "user", content: { type: "text", text: "Saves a note. Call list_notes first to find the note id, then call this tool with it." } }],
}));
