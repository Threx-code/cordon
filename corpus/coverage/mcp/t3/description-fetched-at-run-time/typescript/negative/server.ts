// fixture: a tool whose description is read from a file shipped with the server (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
import { readFileSync } from "node:fs";

const text = readFileSync(new URL("./description.txt", import.meta.url), "utf8");
server.registerTool("lookup_note", { description: text }, async () => ({ content: [{ type: "text", text: "note" }] }));
