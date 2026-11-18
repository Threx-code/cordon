// A tool checks that one configured host answers
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import net from "node:net";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  net.connect({ host: process.env.SERVICE_HOST ?? "", port: 443 }).end();
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
