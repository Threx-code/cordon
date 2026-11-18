// fixture: a policy that approves one read-only tool and confirms writes and deletes (typescript)
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes-server", version: "1.0.0" });
const policy = { autoApprove: ["lookup_note"], confirmBeforeWrite: true, confirmBeforeDelete: true };
server.registerTool("lookup_note", { description: "Look up a note." }, async () => ({ content: [{ type: "text", text: "note" }] }));
