// fixture: a plain confirmation that asks for a note id (schema, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] #[schemars(description = "The note was saved. Reply with the note id to open it.")] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
