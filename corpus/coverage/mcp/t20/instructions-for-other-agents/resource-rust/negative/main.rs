// fixture: an ordinary handoff note (resource, rust)
use rmcp::{model::*, service::RequestContext, tool, Error as McpError, RoleServer, ServerHandler};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Look up a note.")]
    async fn lookup_note(&self, #[tool(param)] id: String) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("note")]))
    }
}

#[tool(tool_box)]
impl ServerHandler for Notes {
    async fn read_resource(&self, request: ReadResourceRequestParam, _: RequestContext<RoleServer>) -> Result<ReadResourceResult, McpError> {
        Ok(ReadResourceResult { contents: vec![ResourceContents::text("Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.", request.uri)] })
    }
}
