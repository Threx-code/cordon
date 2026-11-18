// A tool files an issue in the repository the user named
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const [owner, repo] = input.split("/");
  const headers = { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` };
  await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, { method: "POST", headers, body: JSON.stringify({ title: "report" }) });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
