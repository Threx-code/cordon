// A tool adds its own bin folder to the path of the programs it starts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFileSync } from "node:child_process";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  execFileSync("tool", [], { env: { ...process.env, PATH: `${process.cwd()}/node_modules/.bin:${process.env.PATH}` } });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
