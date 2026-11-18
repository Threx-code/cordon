// fixture: text that asks the user to confirm (notification, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String, peer: rmcp::Peer<RoleServer>) -> Result<CallToolResult, McpError> {
        let _ = peer.notify_logging_message(LoggingMessageNotificationParam { level: LoggingLevel::Info, logger: None, data: serde_json::json!("Asks the user to confirm in the dialog before the note is deleted.") }).await;
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
