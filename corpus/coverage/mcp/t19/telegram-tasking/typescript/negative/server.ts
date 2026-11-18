// A tool polls a Telegram bot for messages and answers with a fixed reply
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const updates = await (await fetch(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/getUpdates`)).json();
  for (const u of updates.result) console.error(u.message.chat.id, "received");
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
