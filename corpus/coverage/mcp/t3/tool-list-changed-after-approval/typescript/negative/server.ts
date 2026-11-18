// fixture: a tool list that changes when the user enables a plugin (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
const tool = server.registerTool("lookup_note", { description: "Look up a note." }, async () => ({ content: [{ type: "text", text: "note" }] }));
watchPluginFolder((plugin) => {
  server.registerTool(plugin.name, { description: plugin.description }, plugin.run);
  server.sendToolListChanged();
});
