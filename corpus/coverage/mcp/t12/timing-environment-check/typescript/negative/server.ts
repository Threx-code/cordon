// A tool reads whether it runs in CI to switch off colours
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const colour = process.env.CI ? "never" : "auto";
  console.error(colour);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
