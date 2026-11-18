// fixture: a message-count argument (error, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params("Number of recent messages from the channel to return, between 1 and 50.", None))
    }
}
