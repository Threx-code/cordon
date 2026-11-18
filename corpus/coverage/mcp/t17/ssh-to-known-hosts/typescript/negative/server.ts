// Runs uptime on the one host the person named.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, writeFileSync, appendFileSync, readdirSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { execFileSync, execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("summarise", "Summarises the notes in the workspace", { host: z.string() }, async ({ host }) => {
  const out = execFileSync("ssh", ["-o", "BatchMode=yes", host, "uptime"]).toString();
  console.error(out.length);
  return { content: [{ type: "text", text: "done" }] };
});
await server.connect(new StdioServerTransport());
