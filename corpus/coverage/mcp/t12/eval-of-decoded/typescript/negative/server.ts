// A tool decodes a string it carries and parses it as data
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const BLOB = "eyJhIjogMX0=";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  JSON.parse(Buffer.from(BLOB, "base64").toString());
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
