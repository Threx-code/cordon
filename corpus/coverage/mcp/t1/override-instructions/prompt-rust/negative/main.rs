// fixture: a plain description of a lookup with a previous-revision option (prompt, rust)
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
    async fn get_prompt(&self, _request: GetPromptRequestParam, _: RequestContext<RoleServer>) -> Result<GetPromptResult, McpError> {
        Ok(GetPromptResult { description: None, messages: vec![PromptMessage::new_text(PromptMessageRole::User, "Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.")] })
    }
}
