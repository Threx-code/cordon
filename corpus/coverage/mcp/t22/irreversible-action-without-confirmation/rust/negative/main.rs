// fixture: a tool that removes one note and requires a confirm argument (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {
    async fn delete_note(&self, id: String, confirm: bool) -> Result<CallToolResult, McpError> {
        if !confirm {
            return Err(McpError::invalid_params("confirmation is required", None));
        }
        std::fs::remove_file(format!("{}/{}.md", std::env::var("NOTES_DIR").unwrap(), id)).ok();
        Ok(CallToolResult::success(vec![Content::text("deleted")]))
    }
}
