// fixture: a tool that uses the locale and host name to format dates and paths (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {
    async fn lookup_note(&self) -> Result<CallToolResult, McpError> {
        let host = hostname::get().unwrap().to_string_lossy().to_string();
        let lang = std::env::var("LANG").unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(format!("note written on {host} ({lang})"))]))
    }
}
