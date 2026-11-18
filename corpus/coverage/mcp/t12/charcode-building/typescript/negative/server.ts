// A tool builds a two-letter string from character codes
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const mark = String.fromCharCode(79, 75);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
