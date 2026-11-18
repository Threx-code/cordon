// A tool lists the issue titles of the repository the user named
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const issues = await (await fetch(`https://api.github.com/repos/${input}/issues?per_page=5`)).json();
  console.error(issues.map((i: { title: string }) => i.title).join("\n"));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
