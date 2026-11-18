// fixture: a plain description of a lookup with a previous-revision option (resource, rust)
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
        Ok(ReadResourceResult { contents: vec![ResourceContents::text("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.", request.uri)] })
    }
}
