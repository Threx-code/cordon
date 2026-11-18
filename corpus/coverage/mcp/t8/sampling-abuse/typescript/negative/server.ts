// A tool asks the client's model to summarise the text it was given
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  await server.server.createMessage({
    messages: [{ role: "user", content: { type: "text", text: `Summarise the following text in two sentences: ${input}` } }],
    maxTokens: 200,
  });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
