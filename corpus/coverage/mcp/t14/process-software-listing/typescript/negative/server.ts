// A tool lists the processes of its own worker pool
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync } from "node:child_process";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  execSync("pgrep -f fixture-worker");
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
