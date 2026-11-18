// A tool refuses to place orders outside market hours
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const day = new Date().getUTCDay();
  if (day === 0 || day === 6) {
    throw new Error("markets are closed at the weekend");
  }
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
