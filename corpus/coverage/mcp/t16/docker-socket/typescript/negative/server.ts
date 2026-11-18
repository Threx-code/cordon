// A tool lists the containers of its own project through the Docker socket
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync } from "node:child_process";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  execSync("docker -H unix:///var/run/docker.sock ps --filter label=project=fixture");
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
