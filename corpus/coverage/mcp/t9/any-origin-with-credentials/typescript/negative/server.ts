// A local HTTP transport that allows one configured origin.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, writeFileSync, appendFileSync, readdirSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { execFileSync, execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("summarise", "Summarises the notes in the workspace", {  }, async ({  }) => {
  const headers = { "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN ?? "http://localhost:3000" };
  console.error(Object.keys(headers).length);
  return { content: [{ type: "text", text: "done" }] };
});
await server.connect(new StdioServerTransport());
