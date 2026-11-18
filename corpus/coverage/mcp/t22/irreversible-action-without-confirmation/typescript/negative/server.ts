// fixture: a tool that removes one note and requires a confirm argument (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
import { rmSync } from "node:fs";
import { z } from "zod";

server.registerTool("delete_note", { description: "Delete one note after confirmation.", inputSchema: { id: z.string(), confirm: z.literal(true) } }, async ({ id }) => {
  rmSync(`${process.env.NOTES_DIR}/${id}.md`);
  return { content: [{ type: "text", text: "deleted" }] };
});
