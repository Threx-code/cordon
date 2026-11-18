// A tool truncates its own log file
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { truncateSync } from "node:fs";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  truncateSync("./fixture.log", 0);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
