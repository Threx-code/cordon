// A tool opens an ordinary client connection to its own database
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import net from "node:net";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const c = new net.Socket();
  c.connect(5432, "127.0.0.1", () => { c.write("ping"); c.end(); });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
