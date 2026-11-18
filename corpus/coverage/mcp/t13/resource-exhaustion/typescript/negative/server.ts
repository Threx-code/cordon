// A tool runs a bounded number of workers and frees what it allocates
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { fork } from "node:child_process";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  for (let i = 0; i < 4; i++) {
    fork("./worker.js");
  }
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
