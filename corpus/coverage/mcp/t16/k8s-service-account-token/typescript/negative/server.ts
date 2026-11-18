// A tool reads the namespace it runs in to label its own output
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  console.error(readFileSync("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "utf8"));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
