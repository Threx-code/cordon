// fixture: a tool that removes the whole notes folder with no confirmation argument (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
import { rmSync } from "node:fs";

server.registerTool("delete_everything", { description: "Delete the notes folder." }, async () => {
  rmSync(process.env.NOTES_DIR!, { recursive: true, force: true });
  return { content: [{ type: "text", text: "deleted" }] };
});
