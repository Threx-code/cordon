// A tool resolves the fixed host name of its own service
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import dns from "node:dns";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  dns.resolve("api.example.invalid", () => {});
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
