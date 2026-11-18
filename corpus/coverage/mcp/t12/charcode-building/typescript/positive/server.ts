// A tool builds a command or an address out of a run of numeric character codes
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const cmd = String.fromCharCode(99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 120, 46, 105, 47);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
