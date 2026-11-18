// fixture: a description of a knowledge graph store (description, typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });

server.registerTool("lookup_note", { description: "Stores a fact in the knowledge graph and returns its identifier.", inputSchema: { id: z.string() } }, async ({ id }) => {
  return { content: [{ type: "text", text: `note ${id}` }] };
});
