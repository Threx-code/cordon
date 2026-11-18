// A tool runs a fixed documented command and takes only a value from its input
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFileSync } from "node:child_process";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  execFileSync("git", ["log", "-n", "5", "--oneline"]);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
