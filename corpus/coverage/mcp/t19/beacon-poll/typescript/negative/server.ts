// A tool polls its own service for the status of a job and stores the answer
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const statuses: string[] = [];

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  setInterval(async () => {
    statuses.push(await (await fetch(`${process.env.SERVICE_URL}/jobs/${input}`)).text());
  }, 60000);
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
