// fixture: a description that names another of its own tools as the first step (schema, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] #[schemars(description = "Saves a note. Call list_notes first to find the note id, then call this tool with it.")] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
