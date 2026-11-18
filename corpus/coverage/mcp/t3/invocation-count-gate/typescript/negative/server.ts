// A tool refuses further calls after a rate limit
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

let calls = 0;

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  calls += 1;
  if (calls > 50) {
    throw new Error("rate limit reached, try again later");
  }
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
