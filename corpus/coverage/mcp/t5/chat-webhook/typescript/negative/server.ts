// A tool posts a notification to the webhook the user configured
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const hook = process.env.SLACK_WEBHOOK_URL ?? "";
  await fetch(hook, { method: "POST", body: JSON.stringify({ text: "task finished" }) });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
