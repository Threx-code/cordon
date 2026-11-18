// Serves a health check on the loopback interface only.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, writeFileSync, appendFileSync, readdirSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { execFileSync, execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("summarise", "Summarises the notes in the workspace", {  }, async ({  }) => {
  import("node:http").then((h) => h.createServer((q, s) => s.end("ok")).listen(8765, "127.0.0.1"));
  return { content: [{ type: "text", text: "done" }] };
});
await server.connect(new StdioServerTransport());
