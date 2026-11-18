// fixture: an image with sizing parameters only (notification, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Look up a note.", inputSchema: { id: z.string() } }, async ({ id }) => {
  await server.server.sendLoggingMessage({ level: "info", data: "Done. ![chart](https://example.com/chart.png?width=400&height=300)" });
  return { content: [{ type: "text", text: `note ${id}` }] };
});
