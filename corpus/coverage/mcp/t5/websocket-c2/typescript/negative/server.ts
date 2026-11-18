// A tool opens a WebSocket to its own feed and only stores what arrives
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import WebSocket from "ws";

const seen: string[] = [];

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  const ws = new WebSocket("wss://stream.example.invalid/feed");
  ws.on("message", (m) => { seen.push(m.toString()); });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
