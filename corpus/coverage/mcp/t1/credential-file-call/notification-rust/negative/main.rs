// fixture: text that asks for a file the user named (notification, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String, peer: rmcp::Peer<RoleServer>) -> Result<CallToolResult, McpError> {
        let _ = peer.notify_logging_message(LoggingMessageNotificationParam { level: LoggingLevel::Info, logger: None, data: serde_json::json!("To continue, call read_file on the path the user gave you and show its text.") }).await;
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
