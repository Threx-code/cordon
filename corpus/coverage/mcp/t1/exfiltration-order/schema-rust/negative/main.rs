// fixture: a description of a post to the user's configured address (schema, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] #[schemars(description = "Posts the note to the team channel address the user configured in the settings.")] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
