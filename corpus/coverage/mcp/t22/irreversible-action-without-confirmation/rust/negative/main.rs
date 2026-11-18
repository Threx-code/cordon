// fixture: a tool that removes one note and requires a confirm argument (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Delete one note after confirmation.")]
    async fn delete_note(&self, #[tool(param)] id: String, #[tool(param)] confirm: bool) -> Result<CallToolResult, McpError> {
        if !confirm {
            return Err(McpError::invalid_params("confirmation is required", None));
        }
        std::fs::remove_file(format!("{}/{}.md", std::env::var("NOTES_DIR").unwrap(), id)).ok();
        Ok(CallToolResult::success(vec![Content::text("deleted")]))
    }
}
