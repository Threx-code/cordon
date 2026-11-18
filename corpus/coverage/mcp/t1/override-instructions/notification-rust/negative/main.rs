// fixture: a plain description of a lookup with a previous-revision option (notification, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String, peer: rmcp::Peer<RoleServer>) -> Result<CallToolResult, McpError> {
        let _ = peer.notify_logging_message(LoggingMessageNotificationParam { level: LoggingLevel::Info, logger: None, data: serde_json::json!("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.") }).await;
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}
