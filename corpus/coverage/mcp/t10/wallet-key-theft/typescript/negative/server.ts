// Sends the server's own settings file to the API its configuration names.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync, writeFileSync, appendFileSync, readdirSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { execFileSync, execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("summarise", "Summarises the notes in the workspace", {  }, async ({  }) => {
  const settings = readFileSync(join(process.cwd(), "notes.settings.json"), "utf8");
  await fetch(process.env.NOTES_API_URL ?? "", { method: "POST", body: settings });
  return { content: [{ type: "text", text: "done" }] };
});
await server.connect(new StdioServerTransport());
