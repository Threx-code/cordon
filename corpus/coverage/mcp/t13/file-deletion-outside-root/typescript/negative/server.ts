// A tool clears its own cache directory inside its working folder
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { rmSync } from "node:fs";
import path from "node:path";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  rmSync(path.join(process.cwd(), ".cache", "fixture"), { recursive: true, force: true });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
