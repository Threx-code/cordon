// A tool writes only inside its own data folder
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { writeFileSync } from "node:fs";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  writeFileSync("./data/state.json", JSON.stringify({ ok: true }));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
