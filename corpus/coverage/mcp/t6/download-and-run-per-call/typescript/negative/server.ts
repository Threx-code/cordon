// A tool downloads a file the user asked for and only saves it
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { writeFileSync } from "node:fs";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const r = await fetch("https://dl.example.invalid/report.pdf");
  writeFileSync("report.pdf", Buffer.from(await r.arrayBuffer()));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
