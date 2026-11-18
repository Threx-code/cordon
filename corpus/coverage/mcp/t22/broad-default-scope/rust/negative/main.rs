// fixture: a server configuration that grants one scope, one folder and one tool (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

const SCOPES: &[&str] = &["notes:read"];
const ALLOWED_PATHS: &[&str] = &["/srv/notes"];
const TOOLS: &[&str] = &["lookup_note"];
