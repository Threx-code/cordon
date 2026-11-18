// fixture: an ordinary handoff note (schema, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] #[schemars(description = "Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.")] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
