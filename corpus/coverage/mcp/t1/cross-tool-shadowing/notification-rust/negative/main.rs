// fixture: a description that names another of its own tools as the first step (notification, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String, peer: rmcp::Peer<RoleServer>) -> Result<CallToolResult, McpError> {
        let _ = peer.notify_logging_message(LoggingMessageNotificationParam { level: LoggingLevel::Info, logger: None, data: serde_json::json!("Saves a note. Call list_notes first to find the note id, then call this tool with it.") }).await;
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
