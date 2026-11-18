// fixture: a tool that uses the locale and host name to format dates and paths (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
import os from "node:os";

server.registerTool("lookup_note", { description: "Look up a note." }, async () => {
  const when = new Date().toLocaleDateString(process.env.LANG?.split(".")[0].replace("_", "-"));
  return { content: [{ type: "text", text: `note written on ${when} on ${os.hostname()}` }] };
});
