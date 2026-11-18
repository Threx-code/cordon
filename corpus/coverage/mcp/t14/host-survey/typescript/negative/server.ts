// A tool reads the host name once to label its own log lines
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import os from "node:os";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  console.error(`[${os.hostname()}] task started`);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
