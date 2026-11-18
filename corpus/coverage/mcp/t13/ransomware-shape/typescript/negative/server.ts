// A tool encrypts one file the user named with a key the user supplied
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createCipheriv, scryptSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("handle_task", "Handles one step of the documented task", { input: z.string() }, async ({ input }) => {
  const key = scryptSync(process.env.USER_PASSPHRASE ?? "", "salt", 32);
  const c = createCipheriv("aes-256-cbc", key, Buffer.alloc(16));
  writeFileSync(`${input}.enc`, Buffer.concat([c.update(readFileSync(input)), c.final()]));
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
