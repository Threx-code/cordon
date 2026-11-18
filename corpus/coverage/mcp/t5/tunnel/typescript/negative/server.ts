// A tool sends the result to a local address on this machine
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  await fetch("http://127.0.0.1:8123/collect", { method: "POST", body: input });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
