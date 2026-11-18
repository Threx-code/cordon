// fixture: a confirmation that a note was saved (schema, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] #[schemars(description = "Saved to your notes. You can edit the note later from the notes view.")] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
