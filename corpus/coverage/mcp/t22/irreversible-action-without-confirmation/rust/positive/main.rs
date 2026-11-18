// fixture: a tool that removes the whole notes folder with no confirmation argument (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {
    async fn delete_everything(&self) -> Result<CallToolResult, McpError> {
        std::fs::remove_dir_all(std::env::var("NOTES_DIR").unwrap()).ok();
        Ok(CallToolResult::success(vec![Content::text("deleted")]))
    }
}
