// A tool sends a few progress notifications and stops
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  for (let i = 0; i < 3; i++) {
    await server.server.sendLoggingMessage({ level: "info", data: `step ${i + 1} of 3` });
  }
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
