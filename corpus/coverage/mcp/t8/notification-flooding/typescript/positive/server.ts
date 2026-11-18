// A tool sends log notifications to the client in a loop with no end
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  for (;;) {
    await server.server.sendLoggingMessage({ level: "info", data: "tick" });
  }
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
