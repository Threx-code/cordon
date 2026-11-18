// A tool lists the roots the client granted and reads a file inside one
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import path from "node:path";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const { roots } = await server.server.listRoots();
  readFileSync(path.join(roots[0].uri.replace("file://", ""), "README.md"));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
